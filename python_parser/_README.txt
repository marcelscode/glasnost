!!!! THIS PROJECT IS NOT YET FULLY READY FOR DISTRIBUTION, PLEASE DO NOT DO SO (2013-03-06 Hadi) !!!!


SETUP:

(0) project prereq: python, django, python-geoip, pyasn (http://code.google.com/p/pyasn/)

(1) download files from mlabs; unzip them as follows ...
(2) download files for ASNDB (see pyasn site or rviews) + MAXMIND 
(3) setup config directories [x2] & db in SETTINGS.PY

(4) python manage.py syncdb
(5) python manage.py runserver

USAGE:
(6) goto http://127.0.0.1:8000/parse/do

(i) choose dates
(ii) choose task1: import logs
        [make sure: paths are correct, files are setup correctly]

        progress is shown in console & final summary in browser. shows: task_import_streams(2012-03-05)     ... 2873 files,  2873 imported, 0+0 malformed

        notes: (1) logs errors to console  (2) will throw exception on duplicates [so either remark .save(), or delete from DB when rerunning]

(iii) choose task2: update geo&asn
		shows: task_update_geodb(2012-03-05)

(iv) IMPORTANT! there is a manual step of updating "SKIP-THIS" here on same cases, (to fix issues like missing protocol, etc...) 
		[todo: add queries here. for examples, see SQLUPDATE.txt]

(v) choose task: parse & analyze
        shows: task_parse_analyze(2012-03-03)
        - can raise exceptions like follows:  ! parse_log2() ex: ''expp18'' @87 (#176    )
            -- these are probably corrupt files that need to be set to skip in (iv)
        
		- will also raise exception on duplicates -- take care of that! [so either remark .save(), or delete from DB when rerunning]
        
	   
POST STEPS: 	   
(7) not necessary, but one could  cross check with mpi results if one wants, this step can be done. [todo: how]
(8) what you are left with and how to use it (e.g. the db fields)   [todo: from paper / emails?]

		