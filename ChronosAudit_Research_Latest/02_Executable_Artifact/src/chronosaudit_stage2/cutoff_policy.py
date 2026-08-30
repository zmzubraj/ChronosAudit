from __future__ import annotations
from dataclasses import dataclass
from datetime import timedelta
import pandas as pd

@dataclass(frozen=True)
class LandmarkPolicy:
    primary_hours_after_deployment: int = 24
    sensitivity_hours_after_deployment: tuple[int,...] = (1,168,720)
    minimum_lead_hours: int = 1

def freeze_landmark(deployment_time: str, incident_time: str | None, policy: LandmarkPolicy=LandmarkPolicy()):
    """Outcome-independent primary cutoff based only on deployment age.

    Incident time is used only to determine eligibility after the cutoff has been
    computed. It never moves the primary cutoff closer to or farther from the event.
    """
    dep=pd.to_datetime(deployment_time,utc=True,errors='raise')
    cutoff=dep+pd.Timedelta(hours=policy.primary_hours_after_deployment)
    eligible=None
    lead=None
    if incident_time:
        inc=pd.to_datetime(incident_time,utc=True,errors='raise')
        lead=(inc-cutoff).total_seconds()/3600
        eligible=bool(lead>=policy.minimum_lead_hours)
    return {'prediction_cutoff_time':cutoff.isoformat(),'primary_landmark_hours':policy.primary_hours_after_deployment,'incident_eligibility':eligible,'lead_hours':lead,'sensitivity_cutoffs':[ (dep+pd.Timedelta(hours=h)).isoformat() for h in policy.sensitivity_hours_after_deployment]}
