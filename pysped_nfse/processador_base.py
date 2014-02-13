# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  Copyright (C) 2013 Proge Informática Ltda (<http://www.proge.com.br>).    #
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
import string
import unicodedata
import xml.etree.ElementTree as ET
from .exception import *


class ProcessadorBase(object):
    def __init__(self, servidor, endereco, certificado, senha, caminho='', servidor_homologacao=''):
        self.servidor = servidor
        self.servidor_homologacao = servidor_homologacao
        self.endereco = endereco
        self.versao = u'1.00'
        self.caminho = caminho
        self._destino = None
        self._obter_dados_do_certificado(certificado, senha)
        self.NS = 'http://www.abrasf.org.br/ABRASF/arquivos/nfse.xsd'
        self.NS_SCHEMA = 'http://www.w3.org/2001/XMLSchema-instance'
        self.namespace = 'xmlns="{}" xmlns:xsi="{}"'.format(self.NS, self.NS_SCHEMA)

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

    def _validar_xml(self, xml, xsd=None):
        xml = self._remover_encode(xml)
        curdir = os.getcwd()
        try:
            xsd_path = os.path.join(os.path.dirname(__file__), 'nfse.xsd')
            esquema = etree.XMLSchema(etree.parse(xsd_path))
        finally:
            os.chdir(curdir)
        esquema.assertValid(etree.fromstring(xml))
        return xml

    def _soap_post(self, connection, xml, xsd_retorno, servico=None):
        connection.request(u'POST', self.endereco, xml, {
            u'Content-Type': u'application/soap+xml; charset=utf-8',
            u'Content-Length': len(xml),
            })

        if self._destino:
            arq = open(self._destino + '-env.xml', 'w')
            arq.write(xml.encode(u'utf-8'))
            arq.close()

        resposta = connection.getresponse()

        if resposta.status != 200:
            raise CommunicationError(resposta.status, resposta.reason)

        resp_xml_str = resposta.read()
        resp_xml = ET.fromstring(resp_xml_str)
        result_str = resp_xml.find(".//{%s}RetornoXML" % self.NS).text
        xsd_retorno.ExternalEncoding = 'utf-8'
        result = xsd_retorno.parseString(result_str.encode('utf-8'))
        
        return result

    def _parse_result(self, result):
        nos_erro = result.Erro
        nos_alerta = result.Alerta

        sucesso = result.Cabecalho.Sucesso

        alertas = {}
        for n in nos_alerta:
            codigo = n.Codigo
            descricao = n.Descricao
            chave_rps = n.ChaveRPS
            if chave_rps:
                chave = chave_rps
            else:
                chave = n.ChaveNFe

            #TODO a chave esta vindo como None, estou setando para o codigo indice, desta forma nao sera possivel enviar em lote.
            try:
                alertas[codigo].append((descricao))
            except KeyError:
                alertas[codigo] = [(descricao)]

        erros = {}
        for n in nos_erro:
            codigo = n.Codigo
            descricao = n.Descricao
            if n.ChaveRPS:
                chave = n.ChaveRPS
            else:
                chave = n.ChaveNFe

            #TODO a chave esta vindo como None, estou setando para o codigo indice, desta forma nao sera possivel enviar em lote.
            try:
                erros[codigo].append((descricao))
            except KeyError:
                erros[codigo] = [(descricao)]

        return (sucesso, erros, alertas)

    def _conectar_servidor(self, xml, service, xsd_retorno, test=False):
        server = test and self.servidor_homologacao or self.servidor

        caminho_temporario = u'/tmp/'
        key_file = caminho_temporario + uuid4().hex
        arq_tmp = open(key_file, 'w')
        arq_tmp.write(self._certificado.chave)
        arq_tmp.close()

        cert_file = caminho_temporario + uuid4().hex
        arq_tmp = open(cert_file, 'w')
        arq_tmp.write(self._certificado.certificado)
        arq_tmp.close()

        xml = self._soap(xml, service)

        connection = HTTPSConnection(server, key_file=key_file, cert_file=cert_file)
        result = self._soap_post(connection, xml, xsd_retorno, service)

        sucesso, erros, alertas = self._parse_result(result)

        if self._destino:
            arq = open(self._destino + '-rec.xml', 'w')
            arq.write(resp_xml_str.encode(u'utf-8'))
            arq.close()

        os.remove(key_file)
        os.remove(cert_file)
        connection.close()

        return (sucesso, result, alertas, erros)

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

    def _obter_xml_da_funcao(self, funcao, assinar=False, xsd=None):
        tmp_dir = u'/tmp/'
        tmp_file_path = tmp_dir + uuid4().hex
        tmp_file = open(tmp_file_path, 'w+')

        funcao.export(tmp_file, 0, namespacedef_=self.namespace)

        tmp_file.seek(0)
        xml = tmp_file.read()
        tmp_file.close()

        if assinar:
            xml = self._certificado.assina_xml(xml)
        return self._validar_xml(xml, xsd)

    def _remove_accents(self, data):
        return ''.join(x for x in unicodedata.normalize('NFKD', unicode(data))\
            if x in string.ascii_letters + ' ').lower()

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
