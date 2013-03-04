# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  Copyright (C) 2012 Proge Informática Ltda (<http://www.proge.com.br>).    #
#                                                                            #
#  Author Daniel Hartmann <daniel@proge.com.br>                              #
#                                                                            #
#  This program is free software: you can redistribute it and/or modify      #
#  it under the terms of the GNU Affero General Public License as            #
#  published by the Free Software Foundation, either version 3 of the        #
#  License, or (at your option) any later version.                           #
#                                                                            #
#  This program is distributed in the hope that it will be useful,           #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of            #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
#  GNU Affero General Public License for more details.                       #
#                                                                            #
#  You should have received a copy of the GNU Affero General Public License  #
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.     #
#                                                                            #
##############################################################################

from pysped_tools.certificado import Certificado
from httplib import HTTPSConnection
import os
from uuid import uuid4
from lxml import etree
from .processador_base import ProcessadorBase
from . import nfse_xsd as xsd


# Classe herdada por que assinatura requer um namespace específico
class Signature(xsd.SignatureType):
    def export(self, outfile, level, namespace_='', name_='SignatureType', namespacedef_='xmlns="http://www.w3.org/2000/09/xmldsig#"'):
        xsd.SignatureType.export(self, outfile, level, namespace_=namespace_, name_=name_, namespacedef_=namespacedef_)

class Base64Binary(xsd.GeneratedsSuper):
    def __init__(self, name='', value=''):
        self.name = name
        self.value = value
    def export(self, outfile, level, namespace_='', name_='DigestValueType', namespacedef_=''):
        xsd.showIndent(outfile, level)
        outfile.write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        if self.value:
            outfile.write('>\n')
            outfile.write(self.value)
            xsd.showIndent(outfile, level)
            outfile.write('</%s%s>\n' % (namespace_, name_))
        else:
            outfile.write('/>\n')

sig_info = xsd.SignedInfoType(
    CanonicalizationMethod=xsd.CanonicalizationMethodType(Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'),
    SignatureMethod=xsd.SignatureMethodType(Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'),
    Reference=[xsd.ReferenceType(
        URI='',
        Transforms=xsd.TransformsType(Transform=[
            xsd.TransformType(Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'),
            xsd.TransformType(Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'),
        ]),
        DigestMethod=xsd.DigestMethodType(Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'),
        DigestValue=Base64Binary('DigestValueType', ''),
        )]
    )
SIGNATURE = Signature(
    SignedInfo=sig_info, 
    SignatureValue=Base64Binary('SignatureValueType', ''),
    KeyInfo=xsd.KeyInfoType(X509Data=[xsd.X509DataType(X509Certificate='')])
    )

class ProcessadorNFSe(ProcessadorBase):
    def enviar_lote_rps(self, lote_rps):
        '''Recepção e Processamento de Lote de RPS'''
        xml = self._obter_xml_da_funcao(
            xsd.EnviarLoteRpsEnvio(LoteRps=lote_rps), True
            )
        return self._conectar_servidor(xml, 'RecepcionarLoteRps')

    def consultar_situacao_lote_rps(self, prestador, protocolo):
        '''Consulta de Situação de Lote de RPS'''
        xml = self._obter_xml_da_funcao(
            xsd.ConsultarSituacaoLoteRpsEnvio(Prestador=prestador,
                                              Protocolo=protocolo)
            )
        return self._conectar_servidor(xml, 'ConsultarSituacaoLoteRps')

    def consultar_nfse_por_rps(self, identificacao_rps, prestador):
        '''Consulta de NFS-e por RPS'''
        xml = self._obter_xml_da_funcao(
            xsd.ConsultarNfseRpsEnvio(IdentificacaoRps=identificacao_rps,
                                      Prestador=prestador)
            )
        return self._conectar_servidor(xml, 'ConsultarNfsePorRps')

    def consultar_lote_rps(self, prestador, protocolo):
        '''Consulta de Lote de RPS'''
        xml = self._obter_xml_da_funcao(
            xsd.ConsultarLoteRpsEnvio(Prestador=prestador, Protocolo=protocolo)
            )
        return self._conectar_servidor(xml, 'ConsultarLoteRps')

    def consultar_nfse(self, prestador, numero_nfse, periodo_emissao, tomador, intermediario_servico):
        '''Consulta de NFS-e'''
        xml = self._obter_xml_da_funcao(
            xsd.ConsultarNfseEnvio(Prestador=prestador,
                                   NumeroNfse=numero_nfse,
                                   PeriodoEmissao=periodo_emissao,
                                   Tomador=tomador,
                                   IntermediarioServico=intermediario_servico)
            )
        return self._conectar_servidor(xml, 'ConsultarNfse')

    def cancelar_nfse(self, pedido):
        '''Cancelamento de NFS-e'''
        xml = self._obter_xml_da_funcao(
            xsd.CancelarNfseEnvio(Pedido=pedido), True
            )
        return self._conectar_servidor(xml, 'CancelarNfse')
