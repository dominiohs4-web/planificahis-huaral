# syntax=docker/dockerfile:1
# PlanificaHIS — PHP 8.2 + Apache para Render / Docker.
# La app escucha en $PORT (Render inyecta 10000; por defecto 80).
FROM php:8.2-apache

ENV PORT=80 \
    APP_ENV=production \
    APACHE_DOCUMENT_ROOT=/var/www/html

RUN apt-get update \
    && apt-get install -y --no-install-recommends libonig-dev \
    && docker-php-ext-install -j"$(nproc)" pdo pdo_mysql mbstring opcache \
    && a2enmod headers rewrite \
    && sed -ri 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf \
    && rm -rf /var/lib/apt/lists/*

COPY docker/php.ini /usr/local/etc/php/conf.d/planificahis.ini
COPY docker/entrypoint.sh /usr/local/bin/planificahis-entrypoint
RUN chmod +x /usr/local/bin/planificahis-entrypoint

WORKDIR /var/www/html

# Se copia solo lo necesario; .dockerignore excluye node_modules, dumps y secretos.
COPY . /var/www/html/

# Limpieza de seguridad: aunque .dockerignore ya los excluye, se elimina
# cualquier residuo de scripts locales, dumps, documentación y metadatos Git.
RUN rm -rf /var/www/html/scripts_hospital \
           /var/www/html/*.sql \
           /var/www/html/*.bat \
           /var/www/html/*.md \
           /var/www/html/sync_cloud_to_local.php \
           /var/www/html/.git \
    && printf 'ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n' \
           > /etc/apache2/conf-available/zz-planificahis-security.conf \
    && a2enconf zz-planificahis-security \
    && apache2ctl -t \
    && chown -R www-data:www-data /var/www/html

EXPOSE 80

ENTRYPOINT ["planificahis-entrypoint"]
CMD ["apache2-foreground"]
