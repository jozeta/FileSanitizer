# Malicious PDF Test Suite

Generated using [jonaslejon/malicious-pdf](https://github.com/jonaslejon/malicious-pdf) in an isolated Docker container.

This test suite covers phone-home callbacks, SSRF, XSS, XXE, NTLM credential theft, and data exfiltration vectors in PDF viewers, parsers, and web services.

## How to Run in Docker

To regenerate or run the Docker container:

```bash
# Build the Docker image
docker build -t malicious-pdf test-files/malicious_pdf

# Generate files to output directory
docker run --rm -v $(pwd)/test-files/malicious_pdf:/output malicious-pdf https://filesanitizer.local/callback --output-dir /output
```

## Test File Catalog

| File Name | Test Description / CVE |
| :--- | :--- |
| `test1.pdf` | CVE-2018-4993 - /GoToE action with UNC path (NTLM callback) |
| `test1_1.pdf` | CVE-2018-4993 - /GoToE action with HTTPS URL |
| `test2.pdf` | XFA form submission - XDP submit event exfiltrates form data |
| `test3.pdf` | JavaScript injection - /OpenAction calls app.openDoc() on remote URL |
| `test4.pdf` | CVE-2019-7089 - XFA external XSLT stylesheet (UNC callback) |
| `test5.pdf` | PDF101 - /URI action triggers DNS/HTTP request |
| `test6.pdf` | PDF101 - /Launch action with external URL |
| `test7.pdf` | PDF101 - /GoToR remote PDF loading |
| `test8.pdf` | PDF101 - /SubmitForm with HTML flags (form data leak) |
| `test9.pdf` | PDF101 - /ImportData external data import |
| `test10.pdf` | CVE-2017-10951 - Foxit this.getURL() JS callback |
| `test11.pdf` | EICAR test file - anti-virus detection string |
| `test12.pdf` | CVE-2014-8453 - XFA FormCalc Post() same-origin exfiltration |
| `test13.pdf` | Request injection - XFA submit CRLF via textEncoding header |
| `test14.svg` | ImageMagick SVG/MSL polyglot - shell injection via authenticate attr |
| `test15.pdf` | FormCalc Post() with custom headers - arbitrary header injection |
| `test16.pdf` | GotoE with javascript: URI - browser XSS via <embed>/<object> |
| `test17.pdf` | CVE-2014-8452 - XMLData.parse() XXE external entity |
| `test18.pdf` | PortSwigger - unescaped parens inject duplicate /A JS action |
| `test19.pdf` | PortSwigger - /AA /PV Screen annotation auto-fires JS on visible |
| `test20.pdf` | PortSwigger - /AA /PC annotation fires JS on page close |
| `test21.pdf` | PortSwigger - /SubmitForm Flags 256 exfiltrates entire PDF |
| `test22.pdf` | PortSwigger - this.submitForm() with cSubmitAs PDF |
| `test23.pdf` | PortSwigger - invisible /Btn widget covers page, JS on click |
| `test24.pdf` | PortSwigger - /Tx widget submitForm() POST (blind SSRF) |
| `test25.pdf` | PortSwigger - getPageNthWord() rendered text exfiltration |
| `test26.pdf` | PortSwigger - /AA /E mouseover annotation JS trigger |
| `test28.pdf` | PortSwigger - unescaped parens inject /URI URL hijacking |
| `test29.pdf` | CVE-2024-4367 - Type1 FontMatrix breaks out of c.transform() (PDF.js) |
| `test30.pdf` | PDF101 - external XObject stream /FS /URL silent page-render callback |
| `test31.pdf` | PDF101 - /S /Thread action with remote FileSpec (Acrobat DC v26 works) |
| `test32.pdf` | PDF101 - /Launch /Win /O /print forces remote fetch |
| `test33_1.pdf` | Acrobat JS - this.submitForm() form submission |
| `test33_2.pdf` | Acrobat JS - this.getURL() URL fetch |
| `test33_3.pdf` | Acrobat JS - app.launchURL() launch URL |
| `test33_4.pdf` | Acrobat JS - app.media.getURLData() media fetch |
| `test33_5.pdf` | Acrobat JS - SOAP.connect() SOAP connection |
| `test33_6.pdf` | Acrobat JS - SOAP.request() SOAP request |
| `test33_7.pdf` | Acrobat JS - this.importDataObject() data import |
| `test33_8.pdf` | Acrobat JS - app.openDoc() open document |
| `test33_9.pdf` | PDF.js/browser - fetch() Web API callback |
| `test33_10.pdf` | PDF.js/browser - XMLHttpRequest Web API callback |
| `test33_11.pdf` | PDF.js/browser - new Image() image request callback |
| `test33_12.pdf` | PDF.js/browser - WebSocket callback |
| `test33_13.pdf` | Adobe 0-day (Apr 2026) - RSS.addFeed() callback |
| `test33_14.pdf` | Adobe 0-day (Apr 2026) - util.readFileIntoStream() + SOAP.request() chain |
| `test33_15.pdf` | Adobe 0-day (Apr 2026) - base64 JS staged in /Tx /V, decoded via getField() |
| `test34_1.pdf` | UNC - image XObject with UNC path (NTLM via page render) |
| `test34_2.pdf` | UNC - /GoToR action with UNC FileSpec |
| `test34_3.pdf` | UNC - /Thread action with UNC FileSpec |
| `test34_4.pdf` | UNC - /URI action with UNC path |
| `test34_5.pdf` | UNC - this.submitForm() with UNC path |
| `test34_6.pdf` | UNC - this.getURL() with UNC path |
| `test34_7.pdf` | UNC - app.launchURL() with UNC path |
| `test34_8.pdf` | UNC - SOAP.connect() with UNC path |
| `test34_9.pdf` | UNC - app.openDoc() with UNC path |
| `test35.pdf` | PDF101 - /Names /JavaScript catalog-level auto-execute trigger |
| `test36.pdf` | CVE-2016-2175/2017-9096 - XXE in /Metadata XMP stream (PDFBox, iText) |
| `test37.pdf` | CVE-2016-2175/2017-9096 - XXE in /AcroForm /XFA stream |
| `test38.pdf` | CVE-2020-29075 - catalog /AA /WC /WS /DS silent DNS callback |
| `test39.pdf` | CVE-2022-28244 - RichMedia annotation embedded HTML/JS (CSP bypass) |
| `test40.pdf` | CVE-2018-5158 - /FunctionType 4 PostScript JS injection (PDF.js) |
| `test41.pdf` | CVE-2018-20065 - /OpenAction /S /URI silent nav (PDFium/Chrome) |
| `test42.pdf` | CVE-2025-66516 - OOB %xxe; param entity in XFA (Tika/Confluence/Jira) |
| `test43.pdf` | CVE-2025-70401 - <img> in Text annotation /T field XSS (Apryse WebViewer) |
