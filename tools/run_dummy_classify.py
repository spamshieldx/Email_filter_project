import csv, os, json
from app.spam_filter import classify_email
try:
    from app import dummy_data
    emails = getattr(dummy_data, 'SAMPLE_EMAILS', [])
except Exception:
    emails = []

out = []
for e in emails:
    folder = classify_email(e.get('subject'), e.get('body'), e.get('sender'), e.get('headers'))
    out.append({
        'id': e.get('id',''),
        'subject': e.get('subject',''),
        'sender': e.get('sender',''),
        'folder_type': folder
    })

out_path = os.path.join(os.getcwd(), 'dummy_classify_report.csv')
with open(out_path, 'w', newline='', encoding='utf-8') as fh:
    writer = csv.DictWriter(fh, fieldnames=['id','subject','sender','folder_type'])
    writer.writeheader()
    for r in out:
        writer.writerow(r)
print('Wrote', out_path)
