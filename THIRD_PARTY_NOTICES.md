# Third-party notices

The connector's own code is covered by `LICENSE`. The components below keep their own licences.

## Bundled in this package

| File | Source | Licence |
|---|---|---|
| `pace_connector/models/ch_PP-OCRv5_det_mobile.onnx`, `en_PP-OCRv5_rec_mobile.onnx`, `ch_ppocr_mobile_v2.0_cls_mobile.onnx` | PaddleOCR models (PaddlePaddle), in the ONNX form distributed by RapidOCR | Apache-2.0 |
| `pace_connector/english_words.txt.gz` | Lower-case entries of the SCOWL word lists (Debian `wamerican`, `wbritish`) | SCOWL licence; the full notice is in `pace_connector/english_words.NOTICE` and must be kept with the file |

## Installed as dependencies

| Package | Licence |
|---|---|
| spaCy, en_core_web_sm model, thinc | MIT |
| RapidOCR | Apache-2.0 |
| ONNX Runtime | MIT |
| pypdfium2 (with PDFium) | Apache-2.0 / BSD-3-Clause |
| Pillow | MIT-CMU (HPND) |
| NumPy, Shapely, OmegaConf | BSD-3-Clause |
| OpenCV (opencv-python-headless) | Apache-2.0 |
| pyclipper, PyYAML, colorlog, six | MIT |
| requests | Apache-2.0 |
| tqdm | MPL-2.0 and MIT |

Optional extras: PaddleOCR and PaddlePaddle (`[paddle]`, Apache-2.0); reportlab and pypdf (`[test]`, BSD).
