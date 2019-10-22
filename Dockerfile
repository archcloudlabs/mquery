FROM python
ENV MALSHARE_TOKEN=""
ENV VT_TOKEN=""
ENV HBA_TOKEN=""
ENV CAESAR_TOKEN=""
COPY ./providers ./opt/providers/
COPY ./mquery.py ./opt/
WORKDIR ./opt/
RUN pip3 install requests
RUN ls /opt/
ENTRYPOINT ["python3", "./mquery.py"]
