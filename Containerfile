FROM docker.io/library/odoo:19.0@sha256:8062dba8327903d0c96daebff88027d41784a060ed3c9ff2dde09f372a45fdd0
USER root
COPY requirements.txt /tmp/soca-requirements.txt
RUN python3 -m pip install --target=/opt/soca-python --no-cache-dir -r /tmp/soca-requirements.txt
ENV PYTHONPATH=/opt/soca-python
COPY --chown=odoo:odoo auth_soca /mnt/extra-addons/auth_soca
USER odoo
