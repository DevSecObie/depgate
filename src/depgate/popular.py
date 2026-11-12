"""Seed list of widely used PyPI packages, used as typosquatting targets.

This is a static snapshot so depgate works offline and has no extra
dependencies. Replace or extend it with a fresh top-packages list
(for example via the `popular_file` policy setting) for production use.
"""

POPULAR = """
boto3 botocore urllib3 requests setuptools certifi charset-normalizer idna
typing-extensions python-dateutil s3transfer packaging six aiobotocore numpy
pyyaml s3fs fsspec pip cryptography grpcio-status cffi pycparser pandas
importlib-metadata pyasn1 rsa zipp attrs jmespath click platformdirs
protobuf pydantic pydantic-core wheel pytz markupsafe jinja2 colorama
filelock tomli virtualenv pyjwt googleapis-common-protos google-api-core
cachetools pluggy pytest wrapt iniconfig exceptiongroup pyasn1-modules
google-auth psutil jsonschema aiohttp yarl multidict frozenlist aiosignal
async-timeout sqlalchemy greenlet docutils pyparsing requests-oauthlib
oauthlib tzdata scipy pillow grpcio openpyxl et-xmlfile decorator
annotated-types beautifulsoup4 soupsieve werkzeug flask itsdangerous
blinker isodate lxml pygments rich markdown-it-py mdurl tqdm httpx httpcore
h11 anyio sniffio distlib pyopenssl tomlkit more-itertools coverage
azure-core azure-storage-blob msal portalocker websocket-client
requests-toolbelt pynacl paramiko bcrypt asn1crypto pexpect ptyprocess
docker gitpython gitdb smmap regex scikit-learn joblib threadpoolctl
matplotlib kiwisolver cycler fonttools contourpy networkx sympy mpmath
torch torchvision transformers tokenizers huggingface-hub safetensors
openai anthropic langchain langchain-core tiktoken fastapi starlette uvicorn
gunicorn django djangorestframework celery redis kombu billiard vine amqp
pymysql psycopg2 psycopg2-binary pymongo elasticsearch black isort flake8
mypy pylint ruff pre-commit tox nox poetry poetry-core hatchling
setuptools-scm build twine keyring jeepney secretstorage termcolor tabulate
python-dotenv dnspython email-validator toml ujson orjson simplejson
marshmallow arrow pendulum babel sentry-sdk prometheus-client opentelemetry-api
opentelemetry-sdk deprecated backoff tenacity retry ply sortedcontainers
xmltodict pycryptodome pycryptodomex selenium playwright scrapy
google-cloud-storage google-cloud-core google-cloud-bigquery
kubernetes ansible ansible-core pywin32 pyinstaller numba llvmlite
pyarrow polars dask xgboost lightgbm tensorflow keras jax jaxlib
nltk spacy gensim opencv-python imageio pytest-cov pytest-mock pytest-xdist
mock responses faker hypothesis
"""

POPULAR_SET = frozenset(POPULAR.split())
