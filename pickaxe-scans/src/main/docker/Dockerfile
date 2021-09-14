FROM openjdk:11

MAINTAINER thomas@netcentric.biz

ADD ${file} /app/
COPY artifact /app/

VOLUME ["/app/output"]
VOLUME ["/app/checks"]
VOLUME ["/app/scan"]

ENTRYPOINT ["/app/entrypoint.sh"]
EXPOSE 8090