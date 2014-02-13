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

from httplib import HTTPSConnection
import xml.etree.ElementTree as ET
from .processador import ProcessadorNFSe, SIGNATURE
from . import nfse_xsd as xsd
from . import rj
import re
import os
from lxml import etree

CODIGO_IBGE_RJ = '04557'
XSD = 'http://www.abrasf.org.br/ABRASF/arquivos/nfse.xsd'
NS_RJ = 'http://notacarioca.rio.gov.br/'
XSD_RJ = 'http://notacarioca.rio.gov.br/WSNacional/XSD/1/nfse_pcrj_v01.xsd'


class FixedInfRPS(xsd.tcInfRps):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='tcInfRps'):
        outfile.write(' xmlns="%s"' % XSD)
        super(FixedInfRPS, self).exportAttributes(
            outfile, level, already_processed, XSD, name_
            )


class ProcessadorNFSeRJ(ProcessadorNFSe):
    def __init__(self, certificado, senha, caminho=''):

        super(ProcessadorNFSeRJ, self).__init__(
            CODIGO_IBGE_RJ,
            certificado,
            senha,
            caminho,
            )

        SIGNATUREKeyInfo = xsd.KeyInfoType(X509Data=xsd.X509DataType(
                X509Certificate=self._certificado.certificado_txt
                )
            )

    def _gerar_xml_envio_nfse(self, rps):
        data_emissao = rps.get('DataEmissao') + 'T00:00:00'
                
        _IdentificacaoRps=xsd.tcIdentificacaoRps(
            Numero=rps.get('NumeroRPS'),
            Serie=rps.get('SerieRPS'),
            Tipo=rps.get('TipoRPS')
            )

        _Valores=xsd.tcValores(
            ValorServicos=rps.get('ValorServicos'),
            ValorDeducoes=rps.get('ValorDeducoes'),
            ValorPis=rps.get('ValorPIS'),
            ValorCofins=rps.get('ValorCOFINS'),
            ValorInss=rps.get('ValorINSS'),
            ValorIr=rps.get('ValorIR'),
            ValorCsll=rps.get('ValorCSLL'),
            IssRetido=rps.get('ISSRetido'),
            ValorIss=rps.get('ValorISS'),
            ValorIssRetido=rps.get('ValorISSRetido'),
            #OutrasRetencoes=rps.get('ValorOutrasRetencoes'),#TODO for now we dont support other retained taxes.
            BaseCalculo=rps.get('ValorBaseCalculo'),
            Aliquota=rps.get('AliquotaServicos'),
            ValorLiquidoNfse=rps.get('ValorLiquido'),
            #DescontoIncondicionado=rps.get(''), #TODO: for now we dont support this.
            #DescontoCondicionado=rps.get('')#TODO: for now we dont support this.
            )
            
        _Servico=xsd.tcDadosServico(
            Valores=_Valores,
            ItemListaServico=rps.get('ItemListaServico'),
            #CodigoCnae=rps.get(''), #TODO support products in nfse invoice.
            CodigoTributacaoMunicipio=rps.get('CodigoServico'),
            Discriminacao=rps.get('Discriminacao'),
            CodigoMunicipio=int(rps.get('Cidade'))
            )

        _Prestador=xsd.tcIdentificacaoPrestador(
            Cnpj=rps.get('CNPJPrestador'),
            InscricaoMunicipal=rps.get('InscricaoMunicipalPrestador')
            )

        if rps.get('TipoInscricaoTomador') == 'J':
            cpf_cnpj = xsd.tcCpfCnpj(Cnpj=rps.get('CPFCNPJTomador'))
        else:
            cpf_cnpj = xsd.tcCpfCnpj(Cpf=rps.get('CPFCNPJTomador'))

        _IdentificacaoTomador=xsd.tcIdentificacaoTomador(
            CpfCnpj=cpf_cnpj,
            InscricaoMunicipal=rps.get('InscricaoMunicipalTomador')
            )

        _Endereco=xsd.tcEndereco(
            Endereco=rps.get('Logradouro'),
            Numero=rps.get('NumeroEndereco'),
            Complemento=rps.get('ComplementoEndereco'),
            Bairro=rps.get('Bairro'),
            CodigoMunicipio=int(rps.get('Cidade')),
            Uf=rps.get('UF'),
            Cep=int(re.sub("[^0-9]", "", rps.get('CEP')))
            )

        _Contato=xsd.tcContato(
            Telefone=rps.get('FoneTomador'),
            Email=rps.get('EmailTomador')
            )

        _Tomador=xsd.tcDadosTomador(
            IdentificacaoTomador=_IdentificacaoTomador,
            RazaoSocial=rps.get('RazaoSocialTomador'),
            Endereco=_Endereco,
            Contato=_Contato
            )
    
        _InfRps=FixedInfRPS(
            IdentificacaoRps=_IdentificacaoRps,
            DataEmissao=data_emissao,
            NaturezaOperacao=rps.get('NaturezaOperacao'),
            OptanteSimplesNacional=rps.get('OptanteSimples'),
            IncentivadorCultural=2, #TODO
            Status=1,#TODO 1-normal,2-cancelado
            Servico=_Servico,
            Prestador=_Prestador,
            Tomador=_Tomador
            )

        rps_obj = xsd.tcRps(
            InfRps=_InfRps
            )

        return self._obter_xml_da_funcao(
            rj.GerarNfseEnvio(Rps=rps_obj),
            False,
            xsd='GerarNfseEnvio'
            )

    def enviar_nfse(self, rps, test=False):
        '''Envio de RPS e geração síncrona de NFSe'''
        self.NS = XSD_RJ
        self.namespace = 'xmlns="{}" xmlns:xsi="{}"'.format(self.NS, self.NS_SCHEMA)

        xml = self._gerar_xml_envio_nfse(rps)
        return self._conectar_servidor(xml, 'GerarNfse', rj.GerarNfseResposta, test)

    def _validar_xml(self, xml, xsd=None):
        xml = self._remover_encode(xml)
        curdir = os.getcwd()
        try:
            if xsd == 'GerarNfseEnvio':
                validation_xsd = os.path.join('rj', 'nfse_pcrj_v01.xsd')
            else:
                validation_xsd = 'nfse.xsd'

            xsd_path = os.path.join(os.path.dirname(__file__), validation_xsd)
            esquema = etree.XMLSchema(etree.parse(xsd_path))
        finally:
            os.chdir(curdir)
        print xml
        esquema.assertValid(etree.fromstring(xml))
        return xml

    def _parse_result(self, result):
        success = False
        errors = {}
        warnings = {}

        try:
            for message in result.ListaMensagemRetorno.MensagemRetorno:
                code = message.Codigo
                try:
                    description = message.Mensagem + ' ' + message.Correcao
                except (AttributeError, TypeError):
                    description = message.Mensagem

                if code.startswith('A'):
                    dic = warnings
                else:
                    dic = errors

                if code != 'E959':
                    try:
                        dic[code].append((description))
                    except KeyError:
                        dic[code] = [(description)]

        except AttributeError:
            success = True

        if len(errors) == 0:
            success = True

        return (success, errors, warnings)

    def _soap_post(self, connection, xml, xsd_retorno, service):
        connection.request(u'POST', self.endereco, xml, {
            u'Content-Type': u'text/xml; charset=utf-8',
            u'Content-Length': len(xml),
            u'SOAPAction': '%s%s' % (NS_RJ, service),
            })

        if self._destino:
            arq = open(self._destino + '-env.xml', 'w')
            arq.write(xml.encode(u'utf-8'))
            arq.close()

        response = connection.getresponse()

        if response.status != 200:
            raise CommunicationError(response.status, response.reason)

        resp_xml_str = response.read()
        print resp_xml_str
        resp_xml = ET.fromstring(resp_xml_str)
        for child in resp_xml: body = child
        for child in body: lote_resp = child

        result_str = lote_resp.find('{%s}outputXML' % NS_RJ).text

        result = rj.parseString(result_str.encode('utf-8'), '%sResposta' % service)
        
        return result

    def _soap(self, xml, servico):
        soap_xml = '''<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope
              SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
              xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
              xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                <SOAP-ENV:Body>
                    <{servico}Request xmlns="http://notacarioca.rio.gov.br/">
                        <inputXML>
                        <![CDATA[
                        {xml}
                        ]]>
                        </inputXML>
                    </{servico}Request>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
            '''.format(servico=servico, xml=xml).encode(u'utf-8')
        print soap_xml

        return soap_xml

    def _gerar_xml_cancelar(self, pedido):
        
        _IdentificacaoNfse=xsd.tcIdentificacaoNfse(
            Numero=pedido.get('NumeroNFe'),
            Cnpj=pedido.get('CPFCNPJRemetente'),
            InscricaoMunicipal=pedido.get('InscricaoPrestador'),
            CodigoMunicipio=04557
            )

        # Código de cancelamento:
        # 1-Erro na emissão
        # 2-Serviço não prestado
        # 3-Duplicidade da nota
        # 9-Outros
        codigo_cancelamento = 1

        _InfPedidoCancelamento=xsd.tcInfPedidoCancelamento(
            IdentificacaoNfse=_IdentificacaoNfse,
            CodigoCancelamento=codigo_cancelamento
            )
       
        pedido_obj = xsd.tcPedidoCancelamento(
            InfPedidoCancelamento=_InfPedidoCancelamento,
            Signature=SIGNATURE
            )

        return self._obter_xml_da_funcao(
            xsd.CancelarNfseEnvio(Pedido=pedido_obj),
            True,
            xsd='CancelarNfseEnvio'
            )

    def cancelar_nfse(self, pedido):
        '''Cancelamento de NFS-e'''
        self.NS = XSD
        self.namespace = 'xmlns="{}" xmlns:xsi="{}"'.format(self.NS, self.NS_SCHEMA)

        xml = self._gerar_xml_cancelar(pedido)
        return self._conectar_servidor(xml, 'CancelarNfse', xsd.CancelarNfseResposta)
