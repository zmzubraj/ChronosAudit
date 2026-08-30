from chronosaudit_stage2.cutoff_policy import freeze_landmark

def test_primary_cutoff_is_deployment_only():
    a=freeze_landmark('2024-01-01T00:00:00Z','2024-02-01T00:00:00Z')
    b=freeze_landmark('2024-01-01T00:00:00Z','2024-03-01T00:00:00Z')
    assert a['prediction_cutoff_time']==b['prediction_cutoff_time']=='2024-01-02T00:00:00+00:00'
    assert a['incident_eligibility'] is True
