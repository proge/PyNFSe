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
from . import nfse_xsd as xsd

#NS = 'http://isscuritiba.curitiba.pr.gov.br/iss/nfse.xsd'
NS = 'http://www.abrasf.org.br/ABRASF/arquivos/nfse.xsd'
NS_SCHEMA = 'http://www.w3.org/2001/XMLSchema-instance'
NAMESPACE_DEF = 'xmlns="{}" xmlns:xsi="{}"'.format(NS, NS_SCHEMA)

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
    #KeyInfo=xsd.KeyInfoType(X509Data=[xsd.X509DataType(X509Certificate='')])
    )

class ProcessadorNFSe(object):
    def __init__(self, servidor, endereco, certificado, senha, caminho=''):
        self.servidor = servidor
        self.endereco = endereco
        self.versao = u'1.00'
        self.caminho = caminho
        self._destino = None
        self._obter_dados_do_certificado(certificado, senha)

    def _obter_dados_do_certificado(self, certificado, senha):
        self._certificado = Certificado()
        self._certificado.arquivo = certificado
        self._certificado.senha = senha
        self._certificado.prepara_certificado_arquivo_pfx()

    def _remover_encode(self, xml):
        aberturas = ('<?xml version="1.0" encoding="utf-8"?>',
            '<?xml version="1.0" encoding="utf-8" ?>',
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<?xml version="1.0" encoding="UTF-8" ?>')

        for a in aberturas:
            xml = xml.replace(a, '')

        return xml

    def _validar_xml(self, xml):
        xml = self._remover_encode(xml)
        curdir = os.getcwd()
        try:
            os.chdir(os.path.split(__file__)[0])
            esquema = etree.XMLSchema(etree.parse('nfse.xsd'))
        finally:
            os.chdir(curdir)
        esquema.assertValid(etree.fromstring(xml))
        return xml

    def _conectar_servidor(self, xml, servico):
        caminho_temporario = u'/tmp/'
        nome_arq_chave = caminho_temporario + uuid4().hex
        arq_tmp = open(nome_arq_chave, 'w')
        arq_tmp.write(self._certificado.chave)
        arq_tmp.close()

        nome_arq_certificado = caminho_temporario + uuid4().hex
        arq_tmp = open(nome_arq_certificado, 'w')
        arq_tmp.write(self._certificado.certificado)
        arq_tmp.close()

        xml = self._soap(xml, servico)
        con = HTTPSConnection(self.servidor, key_file=nome_arq_chave, 
                              cert_file=nome_arq_certificado)
        con.request(u'POST', self.endereco, xml, {
            u'Content-Type': u'application/soap+xml; charset=utf-8', 
            u'Content-Length': len(xml)
            })

        if self._destino:
            arq = open(self._destino + '-env.xml', 'w')
            arq.write(xml.encode(u'utf-8'))
            arq.close()

        resposta = con.getresponse()
        resp_xml = unicode(resposta.read().decode('utf-8'))

        if self._destino:
            arq = open(self._destino + '-rec.xml', 'w')
            arq.write(resp_xml.encode(u'utf-8'))
            arq.close()

        os.remove(nome_arq_chave)
        os.remove(nome_arq_certificado)
        con.close()
        return (resposta.status, resposta.reason, resp_xml)

    def _soap(self, xml, servico):
        return '''<?xml version="1.0" encoding="utf-8"?>
            <soap12:Envelope
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Body>
                    <{servico} xmlns="http://www.e-governeapps2.com.br/">
                        {xml}
                    </{servico}>
                </soap12:Body>
            </soap12:Envelope>
            '''.format(servico=servico, xml=xml).encode(u'utf-8')

    # FIXME: Verificar utilidade dos dois métodos abaixo
    def RemoveSoap(self, xml):
        for x in ('RecepcionarLoteRpsResponse', 'ConsultarLoteRpsResponse', 'CancelarNfseResponse'):
            xml = xml.replace('<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><%s xmlns="http://www.e-governeapps2.com.br/">' % x, '')
            xml = xml.replace('</%s></soap:Body></soap:Envelope>' % x, '')

        return xml

    def Destino(self, emissao=None, serie=None, rps=None, arquivo=None):
        self._destino = None

        if arquivo is not None:
            destino = ('%s/%s/%03d-%09d' % (os.path.join(self.caminho, 'producao' if self.ambiente == 1 else 'homologacao'), emissao.strftime('%Y-%m'), serie, rps))

            if not os.path.exists(destino):
                os.makedirs(destino)

            self._destino = os.path.join(destino, arquivo)

        return self._destino

    def _obter_xml_da_funcao(self, funcao, assinar=False):
        tmp_dir = u'/tmp/'
        tmp_file_path = tmp_dir + uuid4().hex
        tmp_file = open(tmp_file_path, 'w+')

        funcao.export(tmp_file, 0, namespacedef_=NAMESPACE_DEF)

        tmp_file.seek(0)
        xml = tmp_file.read()
        tmp_file.close()

        if assinar:
            xml = self._certificado.assina_xml(xml)

        return self._validar_xml(xml)

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
