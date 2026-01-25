# Render Logs Report

Time range: 2026-01-25T16:41:03Z to 2026-01-25T18:41:03Z (UTC)

Commands used:

```
python (urllib) against https://api.render.com/v1/services/{id} and /v1/logs?ownerId=...&resource=...
```

## srv-d5oh5d14tr6s73eo32fg (sentencinganalysis, background_worker)

Log entries fetched: 20 (hasMore=True)

Recent log excerpts:

```
2026-01-25T18:40:10.587451537Z                     ^^^^^^^^^^^
2026-01-25T18:40:10.587454227Z   File "/usr/local/lib/python3.11/site-packages/gunicorn/app/wsgiapp.py", line 58, in load
2026-01-25T18:40:10.587456667Z     return self.load_wsgiapp()
2026-01-25T18:40:10.587459447Z            ^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:10.587461927Z   File "/usr/local/lib/python3.11/site-packages/gunicorn/app/wsgiapp.py", line 48, in load_wsgiapp
2026-01-25T18:40:10.587464477Z     return util.import_app(self.app_uri)
2026-01-25T18:40:10.587467227Z            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:10.587469907Z   File "/usr/local/lib/python3.11/site-packages/gunicorn/util.py", line 424, in import_app
2026-01-25T18:40:10.587472737Z     app = app(*args, **kwargs)
2026-01-25T18:40:10.587475387Z           ^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:10.587478207Z   File "/app/app.py", line 963, in create_app
2026-01-25T18:40:10.587481207Z     pacer_env_config = validate_pacer_environment_config(
2026-01-25T18:40:10.587483907Z                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:10.587486687Z   File "/app/pacer_env.py", line 119, in validate_pacer_environment_config
2026-01-25T18:40:10.587489587Z     raise ValueError(_mismatch_reason(ENV_QA, ENV_PROD) or "")
2026-01-25T18:40:10.587492427Z ValueError: You are calling Production PCL but authenticating in QA. Use Production credentials and PACER_AUTH_BASE_URL=https://pacer.login.uscourts.gov, or switch PCL_BASE_URL to https://qa-pcl.uscourts.gov/pcl-public-api/rest.
2026-01-25T18:40:10.587985354Z [2026-01-25 18:40:10 +0000] [8] [INFO] Worker exiting (pid: 8)
2026-01-25T18:40:10.829423332Z [2026-01-25 18:40:10 +0000] [7] [ERROR] Worker (pid:8) exited with code 3
2026-01-25T18:40:10.829708026Z [2026-01-25 18:40:10 +0000] [7] [ERROR] Shutting down: Master
2026-01-25T18:40:10.829743646Z [2026-01-25 18:40:10 +0000] [7] [ERROR] Reason: Worker failed to boot.
```



## crn-d5oh5k63jp1c73drr4ng (sentencinganalysis_dockerfile_cron_job, cron_job)

Log entries fetched: 20 (hasMore=True)

Recent log excerpts:

```
2026-01-25T18:40:29.606138181Z   File "/usr/local/lib/python3.11/site-packages/gunicorn/app/wsgiapp.py", line 58, in load
2026-01-25T18:40:29.606139671Z     return self.load_wsgiapp()
2026-01-25T18:40:29.606141221Z            ^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:29.606142771Z   File "/usr/local/lib/python3.11/site-packages/gunicorn/app/wsgiapp.py", line 48, in load_wsgiapp
2026-01-25T18:40:29.606145101Z     return util.import_app(self.app_uri)
2026-01-25T18:40:29.606147791Z            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:29.606150582Z   File "/usr/local/lib/python3.11/site-packages/gunicorn/util.py", line 424, in import_app
2026-01-25T18:40:29.606153111Z     app = app(*args, **kwargs)
2026-01-25T18:40:29.606156082Z           ^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:29.606158712Z   File "/app/app.py", line 963, in create_app
2026-01-25T18:40:29.606161722Z     pacer_env_config = validate_pacer_environment_config(
2026-01-25T18:40:29.606164232Z                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:40:29.606166722Z   File "/app/pacer_env.py", line 119, in validate_pacer_environment_config
2026-01-25T18:40:29.606169362Z     raise ValueError(_mismatch_reason(ENV_QA, ENV_PROD) or "")
2026-01-25T18:40:29.606174502Z ValueError: You are calling Production PCL but authenticating in QA. Use Production credentials and PACER_AUTH_BASE_URL=https://pacer.login.uscourts.gov, or switch PCL_BASE_URL to https://qa-pcl.uscourts.gov/pcl-public-api/rest.
2026-01-25T18:40:29.606204812Z [2026-01-25 18:40:29 +0000] [8] [INFO] Worker exiting (pid: 8)
2026-01-25T18:40:29.776999362Z [2026-01-25 18:40:29 +0000] [7] [ERROR] Worker (pid:8) exited with code 3
2026-01-25T18:40:29.777304468Z [2026-01-25 18:40:29 +0000] [7] [ERROR] Shutting down: Master
2026-01-25T18:40:29.777316079Z [2026-01-25 18:40:29 +0000] [7] [ERROR] Reason: Worker failed to boot.
2026-01-25T18:40:33.205274177Z ❌ Your cronjob failed because of an error: Exited with status 3
```



## srv-d5oh65fgi27c73bqi21g (sentencinganalysis_node, web_service)

Log entries fetched: 20 (hasMore=True)

Recent log excerpts:

```
2026-01-25T18:23:24.615218918Z [2/4] Fetching packages...
2026-01-25T18:23:24.616505646Z [3/4] Linking dependencies...
2026-01-25T18:23:24.625190752Z [4/4] Building fresh packages...
2026-01-25T18:23:24.62960292Z success Saved lockfile.
2026-01-25T18:23:24.632058615Z Done in 0.07s.
2026-01-25T18:23:25.851997384Z [34;1m==>[0;22m [1mUploading build...[22m
2026-01-25T18:23:31.594802995Z [34;1m==>[0;22m [1mUploaded in 4.0s. Compression took 1.8s[22m
2026-01-25T18:23:31.619850195Z [32;1m==>[0;22m [1mBuild successful 🎉[22m
2026-01-25T18:23:34.528285485Z [0;34m[1m==> [0m[1mSetting WEB_CONCURRENCY=1 by default, based on available CPUs in the instance[0m
2026-01-25T18:23:34.544814902Z [0;34m[1m==> [0m[1mDeploying...[0m
2026-01-25T18:23:45.392524538Z [32m[1m==>(B[m [1mRunning 'yarn start'(B[m
2026-01-25T18:23:45.900445972Z yarn run v1.22.22
2026-01-25T18:23:45.984795723Z error Couldn't find a package.json file in "/opt/render/project/src"
2026-01-25T18:23:45.984918945Z info Visit https://yarnpkg.com/en/docs/cli/run for documentation about this command.
2026-01-25T18:23:48.08128289Z [0;31m[1m==> Exited with status 1[0m
2026-01-25T18:23:48.094949488Z [0;34m[1m==> [0m[1mCommon ways to troubleshoot your deploy: https://render.com/docs/troubleshooting-deploys[0m
2026-01-25T18:23:49.36613405Z [32m[1m==>(B[m [1mRunning 'yarn start'(B[m
2026-01-25T18:23:49.687043174Z yarn run v1.22.22
2026-01-25T18:23:49.770959119Z error Couldn't find a package.json file in "/opt/render/project/src"
2026-01-25T18:23:49.77099974Z info Visit https://yarnpkg.com/en/docs/cli/run for documentation about this command.
```



## srv-d5oh6klactks73a1gklg (sentencinganalysis_python_3, web_service)

Log entries fetched: 20 (hasMore=True)

Recent log excerpts:

```
2026-01-25T18:25:03.99720318Z     from . import dml
2026-01-25T18:25:03.99720485Z   File "/opt/render/project/src/.venv/lib/python3.13/site-packages/sqlalchemy/sql/dml.py", line 34, in <module>
2026-01-25T18:25:03.99720652Z     from . import util as sql_util
2026-01-25T18:25:03.99720823Z   File "/opt/render/project/src/.venv/lib/python3.13/site-packages/sqlalchemy/sql/util.py", line 46, in <module>
2026-01-25T18:25:03.99720992Z     from .ddl import sort_tables as sort_tables  # noqa: F401
2026-01-25T18:25:03.99721162Z     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:25:03.99721329Z   File "/opt/render/project/src/.venv/lib/python3.13/site-packages/sqlalchemy/sql/ddl.py", line 30, in <module>
2026-01-25T18:25:03.99721508Z     from .elements import ClauseElement
2026-01-25T18:25:03.99722562Z   File "/opt/render/project/src/.venv/lib/python3.13/site-packages/sqlalchemy/sql/elements.py", line 810, in <module>
2026-01-25T18:25:03.99722771Z     class SQLCoreOperations(Generic[_T_co], ColumnOperators, TypingOnly):
2026-01-25T18:25:03.99722949Z     ...<472 lines>...
2026-01-25T18:25:03.99723114Z                 ...
2026-01-25T18:25:03.997232851Z   File "/opt/render/project/python/Python-3.13.4/lib/python3.13/typing.py", line 1257, in _generic_init_subclass
2026-01-25T18:25:03.99723452Z     super(Generic, cls).__init_subclass__(*args, **kwargs)
2026-01-25T18:25:03.99723618Z     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
2026-01-25T18:25:03.997244871Z   File "/opt/render/project/src/.venv/lib/python3.13/site-packages/sqlalchemy/util/langhelpers.py", line 1988, in __init_subclass__
2026-01-25T18:25:03.997246711Z     raise AssertionError(
2026-01-25T18:25:03.997248521Z     ...<2 lines>...
2026-01-25T18:25:03.997250231Z     )
2026-01-25T18:25:03.997252581Z AssertionError: Class <class 'sqlalchemy.sql.elements.SQLCoreOperations'> directly inherits TypingOnly but has additional attributes {'__firstlineno__', '__static_attributes__'}.
```



## srv-d5ok8u1r0fns73bd6450 (CourtDataPro, web_service)

Log entries fetched: 20 (hasMore=True)

Recent log excerpts:

```
2026-01-25T18:34:09Z clientIP="73.137.103.109" requestID="8c555b22-855a-4c0c" responseTimeMS=5 responseBytes=253 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:14Z clientIP="73.137.103.109" requestID="bd3a4ed6-cb0e-420b" responseTimeMS=3 responseBytes=253 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:14Z clientIP="73.137.103.109" requestID="b67ff94b-7909-4204" responseTimeMS=8 responseBytes=1773 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:14Z clientIP="73.137.103.109" requestID="adf8acbf-5783-4a6b" responseTimeMS=3 responseBytes=246 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:26Z clientIP="73.137.103.109" requestID="d6706f4c-3d50-4fb9" responseTimeMS=4 responseBytes=253 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:26Z clientIP="73.137.103.109" requestID="72638956-7fe5-4728" responseTimeMS=26 responseBytes=1437 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:26Z clientIP="73.137.103.109" requestID="4fc66b29-2e0e-4fdf" responseTimeMS=3 responseBytes=246 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:27Z clientIP="73.137.103.109" requestID="a61ad6ab-abd5-4d7d" responseTimeMS=16 responseBytes=3291 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:28Z clientIP="73.137.103.109" requestID="cbeb5491-9797-4f76" responseTimeMS=6 responseBytes=1773 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:28Z clientIP="73.137.103.109" requestID="07f9d77a-9ac1-4e88" responseTimeMS=3 responseBytes=253 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:28Z clientIP="73.137.103.109" requestID="1c59fe13-327e-4a10" responseTimeMS=2 responseBytes=253 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:28Z clientIP="73.137.103.109" requestID="af11ff16-00eb-41ec" responseTimeMS=4 responseBytes=246 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:28Z clientIP="73.137.103.109" requestID="5450a45a-508a-4c68" responseTimeMS=4 responseBytes=246 userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
2026-01-25T18:34:46Z clientIP="72.60.54.215" requestID="16f4635b-7a81-4510" responseTimeMS=4 responseBytes=366 userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
2026-01-25T18:34:46Z clientIP="72.60.54.215" requestID="40b57780-80ee-47c6" responseTimeMS=3 responseBytes=352 userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
2026-01-25T18:34:47Z clientIP="72.60.54.215" requestID="60da156d-cab8-4d83" responseTimeMS=3 responseBytes=366 userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
2026-01-25T18:34:47Z clientIP="72.60.54.215" requestID="cc3efe48-6eb0-4ab1" responseTimeMS=2 responseBytes=352 userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
2026-01-25T18:38:32Z clientIP="104.23.223.130" requestID="108f38d6-d4ca-4fa8" responseTimeMS=4 responseBytes=366 userAgent="https://courtdatapro.com/wordpress/wp-admin/setup-config.php"
2026-01-25T18:39:16Z clientIP="104.23.223.130" requestID="53540f86-60e8-47cd" responseTimeMS=4 responseBytes=366 userAgent="http://courtdatapro.com/wp-admin/setup-config.php"
2026-01-25T18:39:26Z clientIP="104.23.221.153" requestID="bc1fd213-7b3a-457a" responseTimeMS=2 responseBytes=366 userAgent="https://courtdatapro.com/wp-admin/setup-config.php"
```



## srv-d5oh4p14tr6s73eouac0 (sentencinganalysis, private_service)

Log entries fetched: 20 (hasMore=True)

Recent log excerpts:

```
2026-01-25T18:23:53.661782969Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 1848, in _execute_context
2026-01-25T18:23:53.661785579Z     return self._exec_single_context(
2026-01-25T18:23:53.66178801Z            ^^^^^^^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:23:53.66180425Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 1988, in _exec_single_context
2026-01-25T18:23:53.661807171Z     self._handle_dbapi_exception(
2026-01-25T18:23:53.661810041Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 2344, in _handle_dbapi_exception
2026-01-25T18:23:53.661812701Z     raise sqlalchemy_exception.with_traceback(exc_info[2]) from e
2026-01-25T18:23:53.661815021Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 1969, in _exec_single_context
2026-01-25T18:23:53.661817491Z     self.dialect.do_execute(
2026-01-25T18:23:53.661819951Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/default.py", line 922, in do_execute
2026-01-25T18:23:53.661822581Z     cursor.execute(statement, parameters)
2026-01-25T18:23:53.661825241Z   File "/usr/local/lib/python3.11/site-packages/psycopg/cursor.py", line 117, in execute
2026-01-25T18:23:53.661832872Z     raise ex.with_traceback(None)
2026-01-25T18:23:53.661835872Z sqlalchemy.exc.ProgrammingError: (psycopg.errors.DuplicateTable) relation "ix_pcl_parties_case_id" already exists
2026-01-25T18:23:53.661838432Z [SQL: CREATE INDEX ix_pcl_parties_case_id ON pcl_parties (case_id)]
2026-01-25T18:23:53.661841022Z (Background on this error at: https://sqlalche.me/e/20/f405)
2026-01-25T18:23:53.661847273Z [2026-01-25 18:23:53 +0000] [8] [INFO] Worker exiting (pid: 8)
2026-01-25T18:23:53.920770056Z [2026-01-25 18:23:53 +0000] [7] [ERROR] Worker (pid:8) exited with code 3
2026-01-25T18:23:53.921084323Z [2026-01-25 18:23:53 +0000] [7] [ERROR] Shutting down: Master
2026-01-25T18:23:53.921175698Z [2026-01-25 18:23:53 +0000] [7] [ERROR] Reason: Worker failed to boot.
```



## srv-d5ohj67gi27c73bqo980 (sentencinganalysis_pserv, private_service)

Log entries fetched: 20 (hasMore=True)

Recent log excerpts:

```
2026-01-25T18:23:52.153816387Z     return self._exec_single_context(
2026-01-25T18:23:52.153819128Z            ^^^^^^^^^^^^^^^^^^^^^^^^^^
2026-01-25T18:23:52.153848698Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 1988, in _exec_single_context
2026-01-25T18:23:52.153857998Z     self._handle_dbapi_exception(
2026-01-25T18:23:52.153861428Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 2344, in _handle_dbapi_exception
2026-01-25T18:23:52.153865278Z     raise sqlalchemy_exception.with_traceback(exc_info[2]) from e
2026-01-25T18:23:52.153867398Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 1969, in _exec_single_context
2026-01-25T18:23:52.153880648Z     self.dialect.do_execute(
2026-01-25T18:23:52.153883388Z   File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/default.py", line 922, in do_execute
2026-01-25T18:23:52.153885438Z     cursor.execute(statement, parameters)
2026-01-25T18:23:52.153888298Z   File "/usr/local/lib/python3.11/site-packages/psycopg/cursor.py", line 117, in execute
2026-01-25T18:23:52.153890398Z     raise ex.with_traceback(None)
2026-01-25T18:23:52.153892598Z sqlalchemy.exc.ProgrammingError: (psycopg.errors.DuplicateTable) relation "ix_pcl_parties_case_id" already exists
2026-01-25T18:23:52.153894928Z [SQL: CREATE INDEX ix_pcl_parties_case_id ON pcl_parties (case_id)]
2026-01-25T18:23:52.153897568Z (Background on this error at: https://sqlalche.me/e/20/f405)
2026-01-25T18:23:52.153911509Z [2026-01-25 18:23:52 +0000] [9] [INFO] Worker exiting (pid: 9)
2026-01-25T18:23:52.25368538Z [2026-01-25 18:23:52 +0000] [7] [ERROR] Worker (pid:8) exited with code 3
2026-01-25T18:23:52.259576992Z [2026-01-25 18:23:52 +0000] [7] [ERROR] Worker (pid:9) was sent SIGTERM!
2026-01-25T18:23:52.35413607Z [2026-01-25 18:23:52 +0000] [7] [ERROR] Shutting down: Master
2026-01-25T18:23:52.354172111Z [2026-01-25 18:23:52 +0000] [7] [ERROR] Reason: Worker failed to boot.
```


