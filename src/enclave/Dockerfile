# build enclave_base from https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/containers/Dockerfile.al2
FROM enclave_base

RUN amazon-linux-extras install python3.8
RUN yum install iproute -y

ENV AWS_STS_REGIONAL_ENDPOINTS=regional
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app
# Insert KMS Key ID
ENV KMS_KEY_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

WORKDIR /app

COPY requirements.txt ./
RUN pip3.8 install -r /app/requirements.txt

RUN ls /app
COPY server.py ./
COPY traffic_forwarder.py ./
COPY run.sh ./

RUN mkdir /app/bloom

COPY bloom ./bloom

RUN ls /app
RUN ls /app/bloom

RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]
