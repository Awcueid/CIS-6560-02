import os
import json
import pandas as pd
import numpy as np

def _safe_get_column(df: pd.DataFrame, target_name: str, default_val=0) -> pd.Series:
    """Finds a column case-insensitively ignoring spaces/underscores. 
    Returns a clean pd.Series to prevent scalar AttributeError."""
    normalized_target = target_name.replace('_', '').replace(' ', '').lower()
    for col in df.columns:
        if str(col).replace('_', '').replace(' ', '').lower() == normalized_target:
            return df[col]
    return pd.Series(default_val, index=df.index)

def run_option_b_engine(df: pd.DataFrame) -> pd.DataFrame:
    """Option B: Content-Aware Vulnerability Prioritization Engine."""
    if df.empty:
        return df
        
    engine_df = df.copy()
    
    # Load Taxonomy Configuration
    config_path = os.path.join(os.path.dirname(__file__), 'taxonomy_b_config.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
        
    w = cfg['weights']
    maps = cfg['mappings']
    rules = cfg['rules']
    
    # 1. Severity Score (Scale 0-10 -> 0-100)
    base_score = pd.to_numeric(_safe_get_column(engine_df, 'cvss_base_score', 0), errors='coerce').fillna(0)
    engine_df['v_severity'] = base_score * 10
    
    # 2. Exploited in the Wild
    engine_df['v_exploitation'] = _safe_get_column(engine_df, 'exploitation_context', 'None').astype(str).map(maps['exploitation_context']).fillna(0)
    
    # 3. PoC Availability
    engine_df['v_poc'] = _safe_get_column(engine_df, 'exposure_classification', 'Internal').astype(str).map(maps['exposure_classification']).fillna(0)
    
    # 4. Patch Difficulty
    engine_df['v_patch'] = _safe_get_column(engine_df, 'patch_complexity', 'Medium').astype(str).map(maps['patch_complexity']).fillna(50)
    
    # 5. Compensating Controls & Internet Exposure
    has_controls = _safe_get_column(engine_df, 'compensating_controls', np.nan)
    engine_df['v_controls'] = np.where(has_controls.isna(), rules['missing_control_score'], rules['existing_control_score'])
    
    internet_assets = pd.to_numeric(_safe_get_column(engine_df, 'internet_facing_assets', 0), errors='coerce').fillna(0)
    engine_df.loc[internet_assets > 0, 'v_controls'] = rules['internet_facing_override_score']
    
    # 6. Asset Criticality Density Ratio
    total_assets = pd.to_numeric(_safe_get_column(engine_df, 'total_affected_assets', 1), errors='coerce').fillna(1).replace(0, 1)
    crit_assets = pd.to_numeric(_safe_get_column(engine_df, 'critical_assets', 0), errors='coerce').fillna(0)
    high_assets = pd.to_numeric(_safe_get_column(engine_df, 'high_criticality_assets', 0), errors='coerce').fillna(0)
    engine_df['v_criticality'] = ((crit_assets + high_assets) / total_assets).clip(upper=1.0) * 100
    
    # 7. Governance Status / Risk Acceptance
    engine_df['v_status'] = _safe_get_column(engine_df, 'data_status', 'Active').astype(str).map(maps['data_status']).fillna(100)
    
    # Final Multi-Dimensional Weighting Matrix Summation
    engine_df['Normalized Score'] = (
        (engine_df['v_severity'] * w['severity']) +
        (engine_df['v_exploitation'] * w['exploitation']) +
        (engine_df['v_poc'] * w['poc_availability']) +
        (engine_df['v_patch'] * w['patch_difficulty']) +
        (engine_df['v_controls'] * w['controls']) +
        (engine_df['v_criticality'] * w['asset_criticality']) +
        (engine_df['v_status'] * w['risk_acceptance'])
    )
    
    engine_df['Normalized Score'] = engine_df['Normalized Score'].round(2)
    
    cols_to_drop = [c for c in engine_df.columns if c.startswith('v_')]
    return engine_df.drop(columns=cols_to_drop)
