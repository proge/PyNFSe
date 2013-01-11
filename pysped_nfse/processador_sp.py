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
from . import sp as xsd
from .sp.TiposNFe_v01 import *
from .sp.PedidoEnvioLoteRPS_v01 import *
import re
import base64
import unicodedata
import string

# NS = 'http://isscuritiba.curitiba.pr.gov.br/iss/nfse.xsd'
NS = 'http://www.prefeitura.sp.gov.br/nfe'
NS_SCHEMA = 'http://www.w3.org/2001/XMLSchema-instance'
NS_XSD = 'http://www.w3.org/2001/XMLSchema'
NAMESPACE_DEF = 'xmlns="{}" xmlns:xsi="{}" xmlns:xsd="{}"'.format(
    NS, NS_SCHEMA, NS_XSD
    )

# Classe herdada por que assinatura requer um namespace específico
class Signature(xsd.TiposNFe_v01.SignatureType):
    def export(self, outfile, level, namespace_='', name_='SignatureType',
               namespacedef_='xmlns="http://www.w3.org/2000/09/xmldsig#"'):
        xsd.TiposNFe_v01.SignatureType.export(
            self, outfile, level, namespace_=namespace_, name_=name_,
            namespacedef_=namespacedef_
            )

class Base64Binary(xsd.TiposNFe_v01.GeneratedsSuper):
    def __init__(self, name='', value=''):
        self.name = name
        self.value = value
    def export(self, outfile, level, namespace_='', name_='DigestValueType', namespacedef_=''):
        xsd.TiposNFe_v01.showIndent(outfile, level)
        outfile.write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '',))
        if self.value:
            outfile.write('>\n')
            outfile.write(self.value)
            xsd.TiposNFe_v01.showIndent(outfile, level)
            outfile.write('</%s%s>\n' % (namespace_, name_))
        else:
            outfile.write('/>\n')

class CabecalhoEnvio(xsd.PedidoEnvioLoteRPS_v01.CabecalhoType):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='CabecalhoType'):
        outfile.write(' xmlns=""')
        super(CabecalhoEnvio, self).exportAttributes(
            outfile, level, already_processed, namespace_, name_
            )
class CabecalhoCancelamento(xsd.PedidoCancelamentoNFe_v01.CabecalhoType):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='CabecalhoType'):
        outfile.write(' xmlns=""')
        super(CabecalhoCancelamento, self).exportAttributes(
            outfile, level, already_processed, namespace_, name_
            )
class CabecalhoConsulta(xsd.PedidoConsultaNFe_v01.CabecalhoType):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='CabecalhoType'):
        outfile.write(' xmlns=""')
        super(CabecalhoConsulta, self).exportAttributes(
            outfile, level, already_processed, namespace_, name_
            )
class FixedRPS(tpRPS):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='tpRPS'):
        outfile.write(' xmlns=""')
        super(FixedRPS, self).exportAttributes(
            outfile, level, already_processed, namespace_, name_
            )

sig_info = xsd.TiposNFe_v01.SignedInfoType(
    CanonicalizationMethod=xsd.TiposNFe_v01.CanonicalizationMethodType(Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'),
    SignatureMethod=xsd.TiposNFe_v01.SignatureMethodType(Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'),
    Reference=[xsd.TiposNFe_v01.ReferenceType(
        URI='',
        Transforms=xsd.TiposNFe_v01.TransformsType(Transform=[
            xsd.TiposNFe_v01.TransformType(Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'),
            xsd.TiposNFe_v01.TransformType(Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'),
        ]),
        DigestMethod=xsd.TiposNFe_v01.DigestMethodType(Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'),
        DigestValue=Base64Binary('DigestValueType', ''),
        )]
    )
SIGNATURE = Signature(
    SignedInfo=sig_info,
    SignatureValue=Base64Binary('SignatureValueType', ''),
    KeyInfo=xsd.TiposNFe_v01.KeyInfoType(
        X509Data=[xsd.TiposNFe_v01.X509DataType(X509Certificate='')]
        )
    )

class ProcessadorNFSeSP(object):
    def __init__(self, certificado, senha, caminho=''):
        self.servidor = 'nfe.prefeitura.sp.gov.br'
        # TODO: acho que o endereço deve ser alterado dependendo do tipo de requisição
        self.endereco = '/ws/lotenfe.asmx'
        self.versao = u'1.00'
        self.caminho = caminho
        self._destino = None
        self._obter_dados_do_certificado(certificado, senha)

        SIGNATURE.KeyInfo = xsd.TiposNFe_v01.KeyInfoType(X509Data=
            xsd.TiposNFe_v01.X509DataType(
                X509Certificate=self._certificado.certificado
                )
            )

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
            sp_xsd_path = os.path.join(os.path.dirname(__file__), 'sp')
            xsd_path = os.path.join(sp_xsd_path, 'PedidoEnvioLoteRPS_v01.xsd')
            esquema = etree.XMLSchema(etree.parse(xsd_path))
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
        print xml
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
                    <{servico}Request xmlns="http://www.prefeitura.sp.gov.br/nfe">
                        <VersaoSchema>1</VersaoSchema>
                        <MensagemXML>{xml}</MensagemXML>
                    </{servico}Request>
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

    def _remove_accents(self, data):
        return ''.join(x for x in unicodedata.normalize('NFKD', unicode(data))\
            if x in string.ascii_letters + ' ').lower()

    def _gerar_assinatura(self, inscricao_municipal, serie, numero,
                          data_emissao, tipo_tributacao, status, iss_retido,
                          valor_servicos, valor_deducoes, codigo_servico,
                          cpf_cnpj):
        '''Assinatura do RPS codificada em BASE64.'''
        assinatura = ''

        '''
        Inscrição Municipal (CCM) do Prestador com 8 caracteres. Caso o CCM do
        Prestador tenha menos de 8 caracteres, o mesmo deverá ser completado
        com zeros à esquerda.
        '''
        assinatura += str(inscricao_municipal)

        '''
        Série do RPS com 5 posições. Caso a Série do RPS tenha menos de 5
        caracteres, o mesmo deverá ser completado com espaços em branco à
        direita.
        '''
        assinatura += str(serie)

        '''
        Número do RPS com 12 posições. Caso o Número do RPS tenha menos de 12
        caracteres, o mesmo deverá ser completado com zeros à esquerda.
        '''
        assinatura += str(numero)

        '''Data da emissão do RPS no formato AAAAMMDD.'''
        assinatura += str(re.sub('[^0-9]', '', data_emissao))

        '''
        Tipo de Tributação do RPS com uma posição (sendo T: para Tributação no
        municipio de São Paulo; F: para Tributação fora do municipio de São
        Paulo; I: para Isento; J: para ISS Suspenso por Decisão Judicial).
        '''
        assinatura += str(tipo_tributacao)

        '''
        Status do RPS com uma posição (sendo N: Normal, C: Cancelado; E:
        Extraviado).
        '''
        assinatura += str(status)

        '''
        ISS Retido com uma posição (sendo S: ISS Retido; N: Nota Fiscal sem
        ISS Retido).
        '''
        assinatura += str(iss_retido)

        '''
        Valor dos Serviços com 15 posições e sem separador de milhar e decimal.
        '''
        assinatura += '%015d' % int(re.sub('[^0-9]', '', str(valor_servicos)))

        '''
        Valor das Deduções com 15 posições e sem separador de milhar e decimal.
        '''
        assinatura += '%015d' % int(re.sub('[^0-9]', '', str(valor_deducoes)))

        '''Código do Serviço com 5 posições.'''
        assinatura += str(codigo_servico)

        '''
        CPF/CNPJ do tomador com 14 posições. Sem formatação (ponto, traço,
        barra, ....). Completar com zeros à esquerda caso seja necessário. Se o
        Indicador do CPF/CNPJ for 3 (não-informado), preencher com 14 zeros.
        '''
        assinatura += '%014d' % int(re.sub('[^0-9]', '', str(cpf_cnpj)))

        return base64.b64encode(assinatura)

    def _gerar_assinatura_cancelamento(self, inscricao_municipal, numero):
        '''Assinatura de cancelamento da NFS-e codificada em BASE64.'''
        assinatura = ''

        '''
        Inscrição Municipal (CCM) do Prestador com 8 caracteres. Caso o CCM do
        Prestador tenha menos de 8 caracteres, o mesmo deverá ser completado
        com zeros à esquerda.
        '''
        assinatura += str(inscricao_municipal)

        '''
        Número da NF-e RPS com 12 posições. Caso o Número da NF-e tenha menos
        de 12 caracteres, o mesmo deverá ser completado com zeros à esquerda.
        '''
        assinatura += '%012d' % int(re.sub('[^0-9]', '', str(numero)))

        return base64.b64encode(assinatura)

    def _gerar_xml_envio(self, cabecalho, lote_rps):
        rps_obj_list = []

        for rps in lote_rps:

            # TODO: adicionar validação e mensagens de erro nas linhas abaixo
            cidade = int(rps.get('Cidade'))
            inscr_mun_tomador = int(rps.get('InscricaoMunicipalTomador'))
            inscr_est_tomador = int(rps.get('InscricaoEstadualTomador'))
            numero_rps = int(rps.get('NumeroRPS'))

            endereco = tpEndereco(
                TipoLogradouro=rps.get('TipoLogradouro'),
                Logradouro=rps.get('Logradouro'),
                NumeroEndereco=rps.get('NumeroEndereco'),
                ComplementoEndereco=rps.get('ComplementoEndereco'),
                Bairro=rps.get('Bairro'),
                Cidade=cidade,
                UF=rps.get('UF'),
                CEP=rps.get('EnderecoTomador'),
                )

            rps_obj = FixedRPS(
                Assinatura=self._gerar_assinatura(
                    inscricao_municipal=inscr_mun_tomador,
                    serie=rps.get('SerieRPS'),
                    numero=numero_rps,
                    data_emissao=rps.get('DataEmissao'),
                    tipo_tributacao=rps.get('TributacaoRPS'),
                    status=rps.get('StatusRPS'),
                    iss_retido=rps.get('ISSRetido') and 'S' or 'N',
                    valor_servicos=rps.get('ValorServicos'),
                    valor_deducoes=rps.get('ValorDeducoes'),
                    codigo_servico=rps.get('CodigoServico'),
                    cpf_cnpj=rps.get('CPFCNPJTomador')
                    ),
                ChaveRPS=tpChaveRPS(
                    inscr_mun_tomador,
                    rps.get('SerieRPS'),
                    numero_rps,
                    ),
                TipoRPS=rps.get('TipoRPS', 'RPS-M'),
                DataEmissao=rps.get('DataEmissao'),
                StatusRPS=rps.get('StatusRPS'),
                TributacaoRPS=rps.get('TributacaoRPS'),
                ValorServicos=rps.get('ValorServicos'),
                ValorDeducoes=rps.get('ValorDeducoes'),
                ValorPIS=rps.get('ValorPIS'),
                ValorCOFINS=rps.get('ValorCOFINS'),
                ValorINSS=rps.get('ValorINSS'),
                ValorIR=rps.get('ValorIR'),
                ValorCSLL=rps.get('ValorCSLL'),
                CodigoServico=rps.get('CodigoServico'),
                AliquotaServicos=rps.get('AliquotaServicos'),
                ISSRetido=rps.get('ISSRetido'),
                CPFCNPJTomador=tpCPFCNPJ(CNPJ=rps.get('CPFCNPJTomador')),
                InscricaoMunicipalTomador=inscr_mun_tomador,
                InscricaoEstadualTomador=inscr_est_tomador,
                RazaoSocialTomador=self._remove_accents(
                    rps.get('RazaoSocialTomador')
                    ),
                EnderecoTomador=endereco,
                EmailTomador=rps.get('EmailTomador'),
                Discriminacao=self._remove_accents(rps.get('Discriminacao')),
                )
            rps_obj_list.append(rps_obj)

        valor_total_servicos = '%.02f' % round(cabecalho.get('ValorTotalServicos'), 2)
        valor_total_deducoes = '%.02f' % round(cabecalho.get('ValorTotalDeducoes'), 2)

        cabecalho_obj = CabecalhoEnvio(
            Versao=cabecalho.get('Versao'),
            CPFCNPJRemetente=tpCPFCNPJ(CNPJ=cabecalho.get('CPFCNPJRemetente')),
            transacao=True,
            dtInicio=cabecalho.get('dtInicio'),
            dtFim=cabecalho.get('dtFim'),
            QtdRPS=cabecalho.get('QtdRPS'),
            ValorTotalServicos=valor_total_servicos,
            ValorTotalDeducoes=valor_total_deducoes,
            )

        return self._obter_xml_da_funcao(
            xsd.PedidoEnvioLoteRPS_v01.PedidoEnvioLoteRPS(
                Cabecalho=cabecalho_obj,
                RPS=rps_obj_list,
                Signature=SIGNATURE
                ),
            True
            )

    def enviar_lote_rps(self, cabecalho, lote_rps):
        '''Recepção e Processamento de Lote de RPS'''
        xml = self._gerar_xml_envio(cabecalho, lote_rps)
        return self._conectar_servidor(xml, 'EnvioLoteRPS')

    def testar_envio_lote_rps(self, cabecalho, lote_rps):
        '''Teste de Recepção e Processamento de Lote de RPS'''
        xml = self._gerar_xml_envio(cabecalho, lote_rps)
        return self._conectar_servidor(xml, 'TesteEnvioLoteRPS')

    def consultar_situacao_lote_rps(self, prestador, protocolo):
        '''Consulta de Situação de Lote de RPS'''
        xml = self._obter_xml_da_funcao(
            xsd.PedidoInformacoesLote_v01.PedidoInformacoesLote(
                Prestador=prestador,
                Protocolo=protocolo
                )
            )
        return self._conectar_servidor(xml, 'InformacoesLote')

#    def consultar_nfse_por_rps(self, identificacao_rps, prestador):
#        '''Consulta de NFS-e por RPS'''
#        xml = self._obter_xml_da_funcao(
#            xsd.ConsultarNfseRpsEnvio(IdentificacaoRps=identificacao_rps,
#                                      Prestador=prestador)
#            )
#        return self._conectar_servidor(xml, 'ConsultarNfsePorRps')

    def consultar_nfse(self, dados):
        '''Consulta de NFS-e'''
        inscr_mun_prestador = int(dados.get('InscricaoPrestador'))
        numero_rps = int(dados.get('NumeroRPS'))

        cabecalho = CabecalhoConsulta(
            Versao=dados.get('Versao'),
            CPFCNPJRemetente=tpCPFCNPJ(CNPJ=dados.get('CPFCNPJRemetente')),
            )

        detalhe = xsd.PedidoConsultaNFe_v01.DetalheType(
            ChaveRPS=tpChaveRPS(
                inscr_mun_prestador,
                dados.get('SerieRPS'),
                numero_rps,
                ),
            ChaveNFe=tpChaveNFe(
                InscricaoPrestador=inscr_mun_prestador,
                NumeroNFe=dados.get('NumeroNFe'),
                CodigoVerificacao=dados.get('CodigoVerificacao'),
                ),
            )

        xml = self._obter_xml_da_funcao(
            xsd.PedidoConsultaNFe_v01.PedidoConsultaNFe(
                Cabecalho=cabecalho,
                Detalhe=detalhe,
                Signature=SIGNATURE,
                ))
        return self._conectar_servidor(xml, 'ConsultaNFe')

    def cancelar_nfse(self, dados):
        '''Cancelamento de NFS-e'''

        inscr_mun_tomador = int(dados.get('InscricaoTomador'))
        inscr_mun_prestador = int(dados.get('InscricaoPrestador'))
        numero_rps = int(dados.get('NumeroRPS'))
        numero_nfe = int(dados.get('NumeroNFe'))

        cabecalho = CabecalhoCancelamento(
            Versao=dados.get('Versao'),
            CPFCNPJRemetente=tpCPFCNPJ(CNPJ=dados.get('CPFCNPJRemetente')),
            transacao=True,
            ChaveRPS=tpChaveRPS(
                inscr_mun_tomador,
                dados.get('SerieRPS'),
                numero_rps,
                )
            )
        detalhe = xsd.PedidoCancelamentoNFe_v01.DetalheType(
            ChaveNFe=tpChaveNFe(
                InscricaoPrestador=inscr_mun_prestador,
                NumeroNFe=numero_nfe,
                CodigoVerificacao=dados.get('CodigoVerificacao'),
                ),
            AssinaturaCancelamento=self._gerar_assinatura_cancelamento(
                inscr_mun_prestador,
                numero_nfe,
                ),
            )

        xml = self._obter_xml_da_funcao(
            xsd.PedidoCancelamentoNFe_v01.PedidoCancelamentoNFe(
                Cabecalho=cabecalho,
                Detalhe=detalhe,
                Signature=SIGNATURE,
                ),
            True
            )
        return self._conectar_servidor(xml, 'CancelamentoNFe')
