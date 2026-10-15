# How the connector was tested

All test emails, names, numbers and images here are made up. These figures show how the connector behaves on realistic synthetic data. They are not an accuracy figure for real PaCE email, which will be measured on NTU's sample emails.

## Privacy: ordinary email blocked, names missed

`egress_rates.py` runs every email in `egress_corpus.py` through masking and the second check (egress check), with no engine:

```
PYTHONPATH=. .venv/bin/python benchmarks/egress_rates.py
```

It reports three things:

- **Blocked:** ordinary emails the second check stops. Each one would go to manual handling.
- **Missed:** names still visible in what would be sent.
- **Over-masked:** text masked as a name that isn't one.

Three sets of English enquiries:

- **dev:** 21 emails. The mock emails in `mock_emails/`, two samples shaped like real integration traffic, and the examples.
- **held-out:** 40 emails, written before the name rules were tuned.
- **hard:** 30 emails aimed at the weak spots: names inside sentences, names that are English words, lower-case names, form fields.

Results on 15 Oct 2026:

| Set | Emails / names | Blocked | Names missed | Over-masked |
|---|---|---:|---:|---:|
| dev | 21 / 21 | 0 | 0 | 0 |
| held-out | 40 / 49 | 0 | 0 | 2 |
| hard | 30 / 52 | 0 | 0 | 3 |

**The earlier version** of the second check treated any two capitalised words in a row as a possible name. It blocked 73 of these 91 emails.

**The hard set's first run** was the one done before any tuning on it. It missed 3 of 52 names, all names that are also English words and stand alone ("Grace", "Tony", "Sunny"). That is the fairest estimate of what is still missed.

**Over-masked text** is safe but can hide words the engine needs, for example part of a programme title. Add such words to `pace_connector/public_words.txt`.

`privacy_qualification.py` and `privacy_development_corpus.py` hold a separate frozen set: 100 personal details across names, emails, phones, NRIC/FIN and references, plus 100 business phrases. These are checked in text and in images; `tests/test_m3bq_qualification_runner.py` pins the result.

## OCR

`ocr_backend_qualification.py` checks the attachment pipeline on 20 synthetic images and PDFs: OCR, blackout and re-reading.

`ocr_cpu_comparison.py` compared CPU OCR options on those images plus 8 realistic attachments: receipts, letters (clean, scanned, phone photo), payment screenshots at full and half resolution, and a transcript table. The tests ran on an Intel i7-8700 limited to 4 cores. The connector uses the best option:

| OCR | Words read | Time per page | Peak memory | Personal-detail areas blacked out |
|---|---:|---:|---:|---:|
| **PP-OCRv5 mobile, English recogniser (used)** | 98% | 1.1 s | 0.7 GB | 43 of 44 |
| PP-OCRv4 mobile (earlier default) | 89% (35% on low-resolution screenshots) | 1.0 s | 0.6 GB | 6 of 44 |
| PaddleOCR 3.7 default models (native Paddle) | 99% | 17.9 s | 2.4 GB | 43 of 44 |

Running the comparison needs extra packages; they are listed at the top of the script.
