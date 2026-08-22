# APK Fraud Model Training

Training-only companion for the APK fraud analyzer. It builds and trains a binary
Banking-malware versus Benign classifier from static evidence that the production
analyzer can reproduce.

## Files to upload to Kaggle

Create a **private** Kaggle Dataset containing:

- `kaggle_apk_static_features.csv`
- `kaggle_apk_static_features.metadata.json`

Do not upload APKs, `Banking.tar.gz`, `Benign.tar.gz`, raw IOCs, or API keys.

Create a Kaggle Notebook by importing `kaggle_train.ipynb`, attach the private dataset,
and choose **Save Version → Save & Run All**. The committed run continues in Kaggle's
cloud after the browser or computer is closed. Expected outputs:

- `model-output/apk_static_model.joblib`
- `model-output/metrics.json`

## Dataset generation

Run from this repository on the analysis workstation:

```powershell
python build_dataset.py `
  --backend-root "F:\College\Hackathon\iit_hyd\backend" `
  --banking-dir "F:\College\Hackathon\iit_hyd\test\Banking" `
  --benign-archive "F:\College\Hackathon\iit_hyd\test\a\Benign.tar.gz" `
  --samples-per-class 50 `
  --benign-skip 20 `
  --output data\apk_static_features.csv
```

The exporter is static-only. Benign APKs are streamed into a temporary file one at a
time, hash-verified, analyzed, and deleted. JSONL checkpointing makes interrupted runs
resumable. The first 20 benign members are skipped because they were already used for
rule calibration.

## Leakage controls

- Identity fields and rule risk scores are excluded from model features.
- Train/validation/test partitions are grouped by package identifier.
- The operating threshold is selected on validation data under a minimum-specificity
  policy; the test partition is evaluated only after model selection.
- This CIC-derived model is supporting evidence, not a replacement for explainable rules
  or independent validation.
