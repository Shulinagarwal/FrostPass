FROM public.ecr.aws/lambda/python:3.12@sha256:8a1fd022123cfc44acab0b8447d0ba46f2b385ec51ee15c9074a72627b6f4797 AS base
RUN pip install --no-cache-dir cryptography==50.0.1
COPY common.py /var/task/common.py

FROM base AS intake
COPY intake.py /var/task/intake.py
CMD ["intake.handler"]

FROM base AS grants
COPY grants.py /var/task/grants.py
CMD ["grants.handler"]

FROM base AS broker
COPY broker.py /var/task/broker.py
CMD ["broker.handler"]

FROM base AS witness
COPY witness.py /var/task/witness.py
CMD ["witness.handler"]
