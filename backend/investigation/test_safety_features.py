import copy
import unittest
from unittest.mock import patch

from backend.investigation.enrichment import enrich_report
from backend.investigation.risk_engine import ACTION_RULES, assess_risk, collect_signals

PAYPAL = 'PayPal: Your account is suspended. Immediately verify your password at https://bit.ly/check-account'
JOB = 'You are hired without an interview. Deposit a check for equipment and return the remaining balance immediately. Keep this confidential.'


def report(content=PAYPAL, score=62, answers=None):
    return enrich_report({'risk_score': score, 'confidence': 0.91, 'summary': 'Test evidence', 'recommended_actions': ['Stop and verify independently.']}, content, answers)


class SafetyTests(unittest.TestCase):
    def test_safe_message_and_safety_advice(self):
        for text in ['See you at lunch tomorrow at noon.', 'Never share your password. Do not send money.']:
            result = report(text, 3)
            self.assertEqual(result['risk_score'], 3)
            self.assertEqual(result['attack_chain'], [])
            self.assertEqual(result['verdict'], 'likely_safe')

    def test_paypal_and_job(self):
        for content, signal in [(PAYPAL, 'shortened_url'), (JOB, 'payment_request')]:
            result = report(content)
            self.assertIn(signal, [f['factor'] for f in result['risk_assessment']['risk_factors']])
            self.assertTrue(any(s['status'] == 'predicted' for s in result['attack_chain']))
            self.assertEqual(result['current_stage'], 'unknown')
            self.assertEqual(result['confidence'], 0.91)

    def test_brand_chain_score_ceiling_and_playbook(self):
        result = report(PAYPAL, 95)
        self.assertEqual(result['attack_chain'][0]['name'], 'Brand Impersonation')
        self.assertEqual(result['attack_chain'][0]['status'], 'possible')
        credential_scenario = next(
            scenario for scenario in result['simulations']
            if scenario['action'] == 'enter_credentials'
        )
        self.assertTrue(credential_scenario['score_ceiling_reached'])
        self.assertEqual(credential_scenario['exposure_impact'], 25)
        self.assertTrue(result['safety_playbook'])
        exposed = report(PAYPAL, 60, {'credentials_entered': 'Yes'})
        self.assertTrue(any(
            'Change the password' in step['title']
            for step in exposed['safety_playbook']
        ))

    def test_score_bounds_accounting_and_idempotence(self):
        for score in range(101):
            result = report(score=score, answers={key: 'Yes' for key in ACTION_RULES})
            assessment = result['risk_assessment']
            self.assertEqual(result['risk_score'], score + sum(f['impact'] for f in assessment['risk_factors']))
            self.assertTrue(0 <= result['risk_score'] <= 100)
            self.assertEqual(enrich_report(result, PAYPAL, {key: 'Yes' for key in ACTION_RULES}), result)
            self.assertTrue(all(0 <= s['projected_risk'] <= 100 for s in result['simulations']))

    def test_current_stages_and_no_false_confirmation(self):
        for action in ACTION_RULES:
            result = report(answers={action: 'Yes'})
            self.assertEqual(result['current_stage'], action)
            stop = next(s for s in result['simulations'] if s['action'] == 'ignore_block')
            self.assertEqual(stop['projected_risk'], result['risk_score'])
        for answer in ['No', 'Not sure', 'I might have clicked', 'Yes, but not really', "Yes, I didn't click"]:
            self.assertEqual(report(answers={'link_clicked': answer})['current_stage'], 'unknown')
        result = report(answers={key: 'No' for key in ACTION_RULES})
        self.assertEqual(result['current_stage'], 'before_interaction')
        self.assertLess(result['simulations'][-1]['projected_risk'], result['risk_score'])

    def test_domain_boundaries(self):
        for url in ['https://paypal.com/login', 'https://www.paypal.com/login']:
            self.assertNotIn('brand_domain_mismatch', collect_signals('PayPal ' + url, {}))
        for url in ['https://paypal.com.evil.example/login', 'https://paypal-security.example/login']:
            self.assertIn('brand_domain_mismatch', collect_signals('PayPal ' + url, {}))

    def test_gemini_schema_has_no_dynamic_dictionaries(self):
        import json
        from backend.investigation.types import ModelInvestigationResult
        schema = json.dumps(ModelInvestigationResult.model_json_schema())
        self.assertNotIn('additionalProperties', schema)

    def test_image_validation(self):
        from backend.investigation.vision import ImageReport
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            ImageReport.model_validate({'verdict': 'likely_safe', 'risk_score': 10, 'confidence': 98, 'summary': '', 'extracted_text': ''})

    def test_scenarios_reuse_engine(self):
        result = report(score=20)
        signals = collect_signals(PAYPAL, {})
        scenario = next(s for s in result['simulations'] if s['action'] == 'enter_credentials')
        self.assertEqual(scenario['projected_risk'], assess_risk(20, signals, {'credentials_entered': True}).final_score)


class ApiTests(unittest.TestCase):
    def setUp(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from backend.api.investigations import router
        from backend.services import investigation_service as module
        self.module = module
        self.rows = {}
        self.patcher = patch.object(module, 'investigation_repository')
        self.repo = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        def create(**kwargs):
            row = dict(kwargs, id=str(len(self.rows) + 1), status='pending', created_at='2026-09-26', updated_at='2026-09-26')
            self.rows[row['id']] = row
            return copy.deepcopy(row)
        def save(investigation_id, report, answers=None):
            row = self.rows[investigation_id]
            row['initial_report' if answers is None else 'final_report'] = report
            row.update({key: report[key] for key in ['risk_score', 'risk_level', 'confidence']})
            row['status'] = 'completed' if answers is None else 'updated'
            if answers is not None:
                row['follow_up_answers'] = answers
            return copy.deepcopy(row)
        self.repo.create.side_effect = create
        self.repo.save_initial_report.side_effect = save
        self.repo.save_follow_up_result.side_effect = save
        self.repo.get_by_id.side_effect = lambda key: copy.deepcopy(self.rows.get(key))
        self.repo.list_recent.side_effect = lambda limit: list(self.rows.values())[:limit]
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_image_upload_and_follow_up_persistence(self):
        image_report = report()
        image_report['extracted_text'] = PAYPAL
        with patch.object(self.module, 'analyze_screenshot', return_value=image_report):
            response = self.client.post('/api/investigations/image', files={'file': ('test.png', b'image-fixture', 'image/png')})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertIn('risk_assessment', data)
        path = '/api/investigations/' + data['id']
        for action in ['link_clicked', 'credentials_entered']:
            response = self.client.post(path + '/follow-up', json={'answers': {action: 'Yes'}})
            self.assertEqual(response.status_code, 200, response.text)
        final = response.json()
        self.assertEqual(final['final_report']['current_stage'], 'credentials_entered')
        self.assertTrue(final['final_report']['user_actions']['link_clicked'])
        self.assertEqual(self.client.get(path).json()['final_report'], final['final_report'])
        self.assertEqual(self.client.get('/api/investigations').status_code, 200)
        self.assertEqual(self.client.post(path + '/follow-up', json={'answers': {'invented': 'Yes'}}).status_code, 422)
        self.assertEqual(self.client.get('/api/investigations/missing').status_code, 404)

    def test_model_follow_up_keeps_question_context(self):
        from unittest.mock import Mock
        initial = report()
        initial['follow_up_questions'].append({'question_id': 'Q1', 'question': 'Did you independently verify the sender?'})
        row = self.repo.create(content=PAYPAL)
        self.repo.save_initial_report(investigation_id=row['id'], report=initial)
        result = Mock()
        result.model_dump.return_value = report(score=30)
        with patch.object(self.module, 'investigate_content', return_value=result) as model:
            response = self.client.post('/api/investigations/' + row['id'] + '/follow-up', json={'answers': {'Q1': 'Yes', 'credentials_entered': 'Yes'}})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(model.call_args.args[0].follow_up_answers['Did you independently verify the sender?'], 'Yes')
        self.assertEqual(response.json()['final_report']['current_stage'], 'credentials_entered')

    def test_text_route(self):
        from unittest.mock import Mock
        model = Mock()
        model.model_dump.return_value = report(JOB, 70)
        with patch.object(self.module, 'investigate_content', return_value=model):
            response = self.client.post('/api/investigations', json={'content': JOB})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertIn('simulations', response.json()['initial_report'])

    def test_image_validation_and_cleanup(self):
        from pathlib import Path
        before = set(Path('uploads').glob('*'))
        self.assertEqual(self.client.post('/api/investigations/image', files={'file': ('x.txt', b'text', 'text/plain')}).status_code, 415)
        self.assertEqual(self.client.post('/api/investigations/image', files={'file': ('x.png', b'', 'image/png')}).status_code, 400)
        with patch.object(self.module, 'analyze_screenshot', side_effect=RuntimeError('unavailable')):
            self.assertEqual(self.client.post('/api/investigations/image', files={'file': ('x.png', b'bad', 'image/png')}).status_code, 500)
        self.assertEqual(set(Path('uploads').glob('*')), before)

    def test_image_analysis_survives_persistence_failure(self):
        image_report = report()
        self.repo.create.side_effect = OSError("Supabase DNS unavailable")
        with patch.object(self.module, 'analyze_screenshot', return_value=image_report):
            response = self.client.post(
                '/api/investigations/image',
                files={'file': ('test.png', b'image-fixture', 'image/png')},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['persistence_status'], 'unavailable')
        self.assertNotIn('id', response.json())


class UiTests(unittest.TestCase):
    def test_streamlit_load_and_reports(self):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_file('frontend/streamlit_app.py')
        app.run(timeout=20)
        self.assertFalse(app.exception)
        app.session_state['text_result'] = {'id': 'test', 'initial_report': report(), 'final_report': report(answers={'credentials_entered': 'Yes'})}
        app.run(timeout=20)
        self.assertFalse(app.exception)
        self.assertIn('You are here: credentials entered', [item.value for item in app.info])
        self.assertEqual(len(app.selectbox), 5)


if __name__ == '__main__':
    unittest.main()
