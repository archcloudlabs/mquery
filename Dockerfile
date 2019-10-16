FROM python
ENV MALSHARE_TOKEN=""
ENV VT_TOKEN=""
ENV HBA_TOKEN=""
ENV CAESAR_TOKEN=""
COPY ./src/ ./opt/
WORKDIR ./opt/
RUN pip3 install requests
ENTRYPOINT ["python3", "./mquery.py"]
