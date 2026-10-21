# Performance Note: How LogLens Handles Large Files

The project brief asks how large log files are handled (streaming vs loading the whole file).
This note explains what LogLens does, based on the actual code in `app.py` and `parser.py`.

## Short Answer

LogLens **streams** the file. It never reads the whole log file into memory in one go.
The upload is saved to disk in small chunks, and the analysis then reads the file
**one line at a time**.

## The Three Steps

```
 Browser upload
      |
      |  1. Saved in 64 KB chunks to a temporary file on disk
      v
 Temporary file (on disk, not in RAM)
      |
      |  2. Read ONE line at a time (a Python generator)
      v
 parse_log_line()  ->  detect_attacks()  ->  findings
      |
      |  3. Only the results are sent back to the browser
      v
 Dashboard (counts, chart, tables)
```

### 1. Streaming the upload (`app.py`)
The route reads `uploaded_file.stream` in **64 KB chunks** and writes each chunk to a
`NamedTemporaryFile`. The whole upload is never held in memory at once. The size is
counted while streaming, and the upload is stopped as soon as it passes the 10 MB limit.
Flask's `MAX_CONTENT_LENGTH` setting adds a second safety check (HTTP 413 error).

### 2. Reading line by line (`app.py` and `parser.py`)
`analyze_file()` opens the temporary file and uses `yield from file`, which is a
generator. Python hands over **one line at a time**, so the file is never loaded as a
whole. `parser.py` also has `parse_log_file()`, which reads the same way.

### 3. Processing on the server, not in the browser
All parsing and detection happen in the Python backend. The browser only receives the
finished report, so a large log cannot crash the user's browser tab.

## Why There Is a 10 MB Limit

The live app runs on Render's free plan, which has **512 MB RAM and 0.1 CPU**.
A 10 MB limit keeps the service stable and fast on this small server, and protects it
from very large uploads. The limit is one constant (`MAX_FILE_SIZE`) in `app.py`
and can be raised on a bigger server.

## Honest Limitations

- Lines are **read** as a stream, but the app keeps the parsed records and the findings
  in memory so that brute-force detection can look back over a 60-second window.
  This is fine for 10 MB files. For logs of 500 MB or more, memory use would grow.
- The results page shows every finding. Very large reports would make the page heavy.

## How I Would Scale It Further (Future Work)

1. **Keep only what is needed in memory.** Brute-force detection only needs failed
   (401) login records, so only those would be stored, instead of every parsed line.
2. **Move to a separate worker queue.** Uploads already run as background jobs
  with a Job ID, and the page checks the status. The jobs run inside the web app. A tool such as Celery or RQ with Redis would run the parsing in a separate worker, which suits larger files and many users.
3. **Paginate the results** so only a limited number of findings is shown per page.
4. **Raise the file limit** after moving to a larger server.

## Summary

| Question | Answer |
|---|---|
| Is the whole file loaded into memory? | No. It is streamed. |
| How is the upload handled? | In 64 KB chunks, saved to a temporary file. |
| How is the file read? | One line at a time, using a generator. |
| Where does the processing happen? | In a background thread of the Python backend. |
| What is the file size limit? | 10 MB, because of the free hosting plan. |
| Is there a job queue? | Yes, a simple one. Uploads run as background jobs with a Job ID and a status check. A separate worker (Celery or RQ) is future work. |
