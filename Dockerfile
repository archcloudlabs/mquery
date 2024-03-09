FROM python
ENV MALSHARE_TOKEN=""
ENV VT_TOKEN=""
ENV HBA_TOKEN=""
COPY ./providers ./opt/providers/
COPY ./mquery.py ./opt/
WORKDIR ./opt/
RUN pip3 install requests
# run as non-root user
RUN adduser --system --no-create-home user && \
	chown 100:100 -R /opt/
USER user
# Update action below to download/list/etc...
ENTRYPOINT ["python3", "./mquery.py", "--action", "list"]
