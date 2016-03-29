# Copyright 2016 Brocade Networks, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""ml2_brcd

Revision ID: a84d6a05d397
Revises: kilo
Create Date: 2016-02-09 14:56:58.752583

"""
from alembic import op
from neutron.db.migration import cli
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a84d6a05d397'
down_revision = 'kilo'
branch_labels = None
depends_on = None
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():

    op.create_table('ml2_brocadesvis',
                    sa.Column('tenant_id', sa.String(
                        length=255), nullable=True),
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('svi_id', sa.String(length=36), nullable=False),
                    sa.Column('admin_state_up', sa.Boolean(), nullable=False),
                    sa.Column('ip_address', sa.String(
                        length=36), nullable=True),
                    sa.Column('subnet_mask', sa.String(
                        length=36), nullable=True),
                    sa.PrimaryKeyConstraint('id', 'svi_id'),
                    mysql_engine='InnoDB'
                    )
    op.create_index(op.f('ix_ml2_brocadesvis_tenant_id'),
                    'ml2_brocadesvis', ['tenant_id'], unique=False)
    op.add_column('ml2_brocadeports', sa.Column(
        'host', sa.String(length=255), nullable=True))
