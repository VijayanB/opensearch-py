ARG OPENSEARCH_VERSION
FROM opensearchproject/opensearch:latest

ARG opensearch_path=/usr/share/opensearch

ARG SECURE_INTEGRATION
RUN if [ "$SECURE_INTEGRATION" != "true" ] ; then $opensearch_path/bin/opensearch-plugin remove opensearch-security; fi

COPY --chown=opensearch:opensearch .ci/opensearch/opensearch-run.sh $opensearch_path/

CMD /usr/share/opensearch/opensearch-run.sh
