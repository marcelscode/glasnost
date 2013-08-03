Glasnost Python Parser
By: Hadi Asghari, the Network is Aware Project <http://dpi.ischool.syr.edu/Home.html>

The Python Parser is a Python/Django project that helps to make use of GLASNOST data for high-level research questions.

The projects helps in the following: 
	1. Extracting the main outcome or "verdict" from test logs. This is an update of the original algorithm provided by the authors, covering corner cases and "abnormal" tests.	
	2. Adding historical based geo-leocation + ASN data
	3. Storing the output in SQL, easing making aggregated (ISP/country level) datasets.

Build & run steps are provided below. For details of the parser, see the document "BUILDING VERDICTS WITH GLASNOST PYTHON PARSER"


-----------------------------------------------------
I. SETUP:

(1) Install project prerequisites: Python, Django, python-geoip, PyASN (http://code.google.com/p/pyasn/)

(2) Download historical IPASN database for PyASN (available on its site) & for MAXMIND GeoIP (purchase via http://www.maxmind.com/en/country)

(3) Configure the directories GLASNOST_ROOT & GEOASN_ROOT and the default database connection in SETTINGS.PY

(4) Download glasnost data files from mlabs; unzip them without the .dump files:
gsutil cp -r gs://m-lab/glasnost/20YY/MM/* LOCALDIR
find . | grep tgz | xargs -I xxx tar vxzf xxx  --exclude=*.dump

(5) Run: "python manage.py syncdb"


--------------------------------------------------
II. PARSING & BUILDING VERDICTS:

(1) Run: "python manage.py runserver"

(2) Go to "http://127.0.0.1:8000/parse/do" in browser

(3) Select correct date range and choose task1: import logs
        progress is shown in console & final summary in browser. e.g.:
            shows: task_import_streams(20xx-xx-xx)     ... 2873 files,  2873 imported, 0+0 malformed

        notes:
         - make sure paths are correct. log files can be .log.gz, or .log
         - logs errors to console
         - will throw exception on duplicates (so either remark .save(), or delete from DB when rerunning)

(4) Choose task: update geo&asn
		shows: task_update_geodb(20xx-xx-xx)

(5) Manually set some tests to be skipped in processing by setting "SKIP-THIS" in database, e.g. invalid protocols, etc. The " SQL sanity check"  document contains details. Mainly:
	update glasnost_test set skip_reason ='Google test-IP'  where skip_this=1 and (client_ip='64.9.225.190' or client_ip='64.9.225.99');
       update glasnost_test set skip_this=1, skip_reason='Flows not 24' where num_flows<>24 and skip_this=0 and start_time>='2010-04-20';


(6) Choose task: parse & analyze
        shows: task_parse_analyze(20xx-xx-xx)
        notes:
        - can raise exceptions like follows:  ! parse_log2() ex: ''expp18'' @87 (#176    )
          these are probably corrupt files that need to be set to skip in step (5)
   	 - will also raise exception on duplicates -- take care of that! (so either remark .save(), or delete from DB when rerunning)
         

--------------------------------------------------
III. POST STEPS:

(1) At this point the database tables "glasnost_test" & "glasnost_verdict" should be populated accordingly with test results.
The file "glasnost DB fields.docx" explains the important table fields.

(2) Export to CSV - see export_csv.sql.





