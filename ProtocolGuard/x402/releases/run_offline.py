"""Re-run the fixed historical snapshot locally. Does not refresh live tags or use models."""
import subprocess,sys
from pathlib import Path
BASE=Path(__file__).resolve().parent
for script in ['audit.py','normalize_scope.py','rebuild_contexts.py','enrich_intervals.py','refresh_dynamic.py','schema_refresh.py','annotate_inputs.py','package_scope.py','add_diffs.py','render.py']:
    print('Running '+script,flush=True)
    subprocess.run([sys.executable,str(BASE/script)],check=True)
