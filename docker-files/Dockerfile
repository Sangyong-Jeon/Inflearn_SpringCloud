FROM mysql:8.0.33
ENV MYSQL_ROOT_PASSWORD test1357
ENV MYSQL_ALLOW_EMPTY_PASSWORD asdf
ENV MYSQL_RANDOM_ROOT_PASSWORD asdf
ENV MYSQL_DATABASE mydb
COPY ./mysql_data/mysql /var/lib/mysql
EXPOSE 3306
ENTRYPOINT ["mysqld"]