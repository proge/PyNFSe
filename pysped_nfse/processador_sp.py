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

import os
from lxml import etree
from .processador_base import ProcessadorBase
from . import sp as xsd
from .sp.TiposNFe_v01 import *
from .sp.PedidoEnvioLoteRPS_v01 import *
import re
import base64
import M2Crypto
import hashlib
import datetime


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
class DetalheCancelamento(xsd.PedidoCancelamentoNFe_v01.DetalheType):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='DetalheType'):
        outfile.write(' xmlns=""')
        super(DetalheCancelamento, self).exportAttributes(
            outfile, level, already_processed, namespace_, name_
            )
class CabecalhoConsulta(xsd.PedidoConsultaNFe_v01.CabecalhoType):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='CabecalhoType'):
        outfile.write(' xmlns=""')
        super(CabecalhoConsulta, self).exportAttributes(
            outfile, level, already_processed, namespace_, name_
            )
class CabecalhoConsultaPeriodo(
                               xsd.PedidoConsultaNFePeriodo_v01.CabecalhoType):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='CabecalhoType'):
        outfile.write(' xmlns=""')
        super(CabecalhoConsultaPeriodo, self).exportAttributes(
            outfile, level, already_processed, namespace_, name_
            )
class DetalheConsulta(xsd.PedidoConsultaNFe_v01.DetalheType):
    def exportAttributes(self, outfile, level, already_processed,
                         namespace_='', name_='DetalheType'):
        outfile.write(' xmlns=""')
        super(DetalheConsulta, self).exportAttributes(
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

class ProcessadorNFSeSP(ProcessadorBase):
    def __init__(self, certificado, senha, caminho=''):
        super(ProcessadorNFSeSP, self).__init__(
            'nfe.prefeitura.sp.gov.br',
            #'testenfe.prefeitura.sp.gov.br',
            '/ws/lotenfe.asmx',
            certificado,
            senha,
            caminho
            )

        self.NS = 'http://www.prefeitura.sp.gov.br/nfe'
        NS_SCHEMA = 'http://www.w3.org/2001/XMLSchema-instance'
        NS_XSD = 'http://www.w3.org/2001/XMLSchema'
        self.namespace = 'xmlns="{}" xmlns:xsi="{}" xmlns:xsd="{}"'.format(
            self.NS, NS_SCHEMA, NS_XSD
            )

        SIGNATURE.KeyInfo = xsd.TiposNFe_v01.KeyInfoType(X509Data=
            xsd.TiposNFe_v01.X509DataType(
                X509Certificate=self._certificado.certificado
                )
            )

    def _validar_xml(self, xml, xsd):
        xml = self._remover_encode(xml)
        curdir = os.getcwd()
        try:
            sp_xsd_path = os.path.join(os.path.dirname(__file__), 'sp')
            file_name = '{}.xsd'.format(xsd)
            xsd_path = os.path.join(sp_xsd_path, file_name)
            esquema = etree.XMLSchema(etree.parse(xsd_path))
        finally:
            os.chdir(curdir)
        esquema.assertValid(etree.fromstring(xml))
        return xml

    def _soap(self, xml, servico):
        return '''<?xml version="1.0" encoding="utf-8"?>
            <soap12:Envelope
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Body>
                    <{servico}Request
                        xmlns="http://www.prefeitura.sp.gov.br/nfe">
                        <VersaoSchema>1</VersaoSchema>
                        <MensagemXML>
                        <![CDATA[
                        {xml}
                        ]]>
                        </MensagemXML>
                    </{servico}Request>
                </soap12:Body>
            </soap12:Envelope>
            '''.format(servico=servico, xml=xml).encode(u'utf-8')

    def _gerar_assinatura(self, inscricao_municipal, serie, numero,
                          data_emissao, tipo_tributacao, status, iss_retido,
                          valor_servicos, valor_deducoes, codigo_servico,
                          tipo_inscricao, cpf_cnpj):
        '''Assinatura do RPS codificada em BASE64.'''
        assinatura = ''

        '''
        Inscrição Municipal (CCM) do Prestador com 8 caracteres. Caso o CCM do
        Prestador tenha menos de 8 caracteres, o mesmo deverá ser completado
        com zeros à esquerda.
        '''
        assinatura += '%08d' % int(
            re.sub('[^0-9]', '', str(inscricao_municipal))
            )

        '''
        Série do RPS com 5 posições. Caso a Série do RPS tenha menos de 5
        caracteres, o mesmo deverá ser completado com espaços em branco à
        direita.
        '''
        assinatura += '%-5s' % re.sub('[^0-9]', '', str(serie))

        '''
        Número do RPS com 12 posições. Caso o Número do RPS tenha menos de 12
        caracteres, o mesmo deverá ser completado com zeros à esquerda.
        '''
        assinatura += '%012d' % int(re.sub('[^0-9]', '', str(numero)))

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
        # FIXME: garantir duas casas decimais
        assinatura += '%015d' % int(re.sub('[^0-9]', '', str(valor_servicos)))

        '''
        Valor das Deduções com 15 posições e sem separador de milhar e decimal.
        '''
        # FIXME: garantir duas casas decimais
        assinatura += '%015d' % int(re.sub('[^0-9]', '', str(valor_deducoes)))

        '''Código do Serviço com 5 posições.'''
        assinatura += '%05d' % int(re.sub('[^0-9]', '', str(codigo_servico)))

        '''Tipo de inscrição. 1 (CPF), 2 (CNPJ) e 3 (não informado).'''
        assinatura += tipo_inscricao == 'J' and '2' or '1'

        '''
        CPF/CNPJ do tomador com 14 posições. Sem formatação (ponto, traço,
        barra, ....). Completar com zeros à esquerda caso seja necessário. Se o
        Indicador do CPF/CNPJ for 3 (não-informado), preencher com 14 zeros.
        '''
        if not cpf_cnpj:
            cpf_cnpj = 0
        assinatura += '%014d' % int(re.sub('[^0-9]', '', str(cpf_cnpj)))

        self._certificado.prepara_certificado_arquivo_pfx()

        pkey = M2Crypto.RSA.load_key_string(self._certificado.chave)
        signature = pkey.sign(hashlib.sha1(assinatura).digest(), 'sha1')

        return base64.b64encode(signature)

    def _gerar_assinatura_cancelamento(self, inscricao_municipal, numero):
        '''Assinatura de cancelamento da NFS-e codificada em BASE64.'''
        assinatura = ''

        '''
        Inscrição Municipal (CCM) do Prestador com 8 caracteres. Caso o CCM do
        Prestador tenha menos de 8 caracteres, o mesmo deverá ser completado
        com zeros à esquerda.
        '''
        assinatura += '%08d' % int(
            re.sub('[^0-9]', '', str(inscricao_municipal))
            )

        '''
        Número da NF-e RPS com 12 posições. Caso o Número da NF-e tenha menos
        de 12 caracteres, o mesmo deverá ser completado com zeros à esquerda.
        '''
        assinatura += '%012d' % int(re.sub('[^0-9]', '', str(numero)))

        self._certificado.prepara_certificado_arquivo_pfx()

        pkey = M2Crypto.RSA.load_key_string(self._certificado.chave)
        signature = pkey.sign(hashlib.sha1(assinatura).digest(), 'sha1')

        return base64.b64encode(signature)

    def _gerar_xml_envio(self, cabecalho, lote_rps):
        rps_obj_list = []

        for rps in lote_rps:

            # TODO: adicionar validação e mensagens de erro nas linhas abaixo
            cidade = int(rps.get('Cidade'))

            inscr_mun_tomador = rps.get('InscricaoMunicipalTomador')
            if inscr_mun_tomador:
                inscr_mun_tomador = int(inscr_mun_tomador)

            inscr_est_tomador = rps.get('InscricaoEstadualTomador')
            if inscr_est_tomador:
                inscr_est_tomador = int(inscr_est_tomador)

            inscr_mun_prestador = cabecalho.get('InscricaoMunicipalPrestador')
            if inscr_mun_prestador:
                inscr_mun_prestador = int(inscr_mun_prestador)

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

            valor_servicos = rps.get('ValorServicos')
            if valor_servicos == 0.0:
                valor_servicos = 0

            assinatura = self._gerar_assinatura(
                inscricao_municipal=inscr_mun_prestador,
                serie=rps.get('SerieRPS'),
                numero=numero_rps,
                data_emissao=rps.get('DataEmissao'),
                tipo_tributacao=rps.get('TributacaoRPS'),
                status=rps.get('StatusRPS'),
                iss_retido=rps.get('ISSRetido') and 'S' or 'N',
                valor_servicos=rps.get('ValorServicos'),
                valor_deducoes=rps.get('ValorDeducoes'),
                codigo_servico=rps.get('CodigoServico'),
                tipo_inscricao=rps.get('TipoInscricaoTomador'),
                cpf_cnpj=rps.get('CPFCNPJTomador'),
                )
            rps_obj = FixedRPS(
                Assinatura=assinatura,
                ChaveRPS=tpChaveRPS(
                    inscr_mun_prestador,
                    rps.get('SerieRPS'),
                    numero_rps,
                    ),
                TipoRPS=rps.get('TipoRPS', 'RPS-M'),
                DataEmissao=rps.get('DataEmissao'),
                StatusRPS=rps.get('StatusRPS'),
                TributacaoRPS=rps.get('TributacaoRPS'),
                ValorServicos=valor_servicos,
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
                EmailTomador=rps.get('EmailTomador') or None,
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
            True,
            xsd='PedidoEnvioLoteRPS_v01'
            )

    def enviar_lote_rps(self, cabecalho, lote_rps):
        '''Recepção e Processamento de Lote de RPS'''
        xml = self._gerar_xml_envio(cabecalho, lote_rps)
        return self._conectar_servidor(
            xml, 'EnvioLoteRPS', xsd.RetornoEnvioLoteRPS_v01
            )

    def testar_envio_lote_rps(self, cabecalho, lote_rps):
        '''Teste de Recepção e Processamento de Lote de RPS'''
        xml = self._gerar_xml_envio(cabecalho, lote_rps)
        return self._conectar_servidor(
            xml, 'TesteEnvioLoteRPS', xsd.RetornoEnvioLoteRPS_v01
            )

    def consultar_situacao_lote_rps(self, prestador, protocolo):
        '''Consulta de Situação de Lote de RPS'''
        xml = self._obter_xml_da_funcao(
            xsd.PedidoInformacoesLote_v01.PedidoInformacoesLote(
                Prestador=prestador,
                Protocolo=protocolo
                ),
            xsd='PedidoInformacoesLote_v01'
            )
        return self._conectar_servidor(
            xml, 'InformacoesLote', xsd.RetornoInformacoesLote_v01
            )

    def consultar_nfse_por_rps(self, identificacao_rps, prestador):
        '''Consulta de NFS-e por RPS'''
        raise NotImplementedError(u'Método não implementado para SP.')

    def consultar_nfse(self, dados):
        '''Consulta de NFS-e'''
        inscr_mun_prestador = int(dados.get('InscricaoPrestador'))

        cabecalho = CabecalhoConsulta(
            Versao=dados.get('Versao'),
            CPFCNPJRemetente=tpCPFCNPJ(CNPJ=dados.get('CPFCNPJRemetente')),
            )

        # Usar ChaveRPS or ChaveNFe, nunca ambos
        if dados.get('SerieRPS'):
            numero_rps = int(dados.get('NumeroRPS'))
            detalhe = DetalheConsulta(
                ChaveRPS=tpChaveRPS(
                    inscr_mun_prestador,
                    dados.get('SerieRPS'),
                    numero_rps,
                    )
                )
        else:
            detalhe = DetalheConsulta(
                ChaveNFe=tpChaveNFe(
                    InscricaoPrestador=inscr_mun_prestador,
                    NumeroNFe=dados.get('NumeroNFe'),
                    CodigoVerificacao=dados.get('CodigoVerificacao'),
                    )
                )

        xml = self._obter_xml_da_funcao(
            xsd.PedidoConsultaNFe_v01.PedidoConsultaNFe(
                Cabecalho=cabecalho,
                Detalhe=[detalhe],
                Signature=SIGNATURE,
                ),
            True,
            xsd='PedidoConsultaNFe_v01'
            )
        return self._conectar_servidor(
            xml, 'ConsultaNFe', xsd.RetornoConsulta_v01
            )

    def consultar_nfse_emitidas(self, dados, numero_pagina=1):
        '''Consulta de NFS-e emitidas'''
        inscr_mun_prestador = int(dados.get('InscricaoPrestador'))

        data_inicio = dados.get('DataInicio')
        data_fim = dados.get('DataFim')

        if not data_inicio:
            '''
            Se não for informada data de início, obtém o início do ano da data
            de fim. Se não for informada data de início nem de fim, obtém o
            início do ano atual.
            '''
            if data_fim:
                data_fim_obj = datetime.datetime.strptime(data_fim, '%Y-%m-%d')
                ano_atual = int(data_fim_obj.strftime('%Y'))
            else:
                ano_atual = int(datetime.datetime.today().strftime('%Y'))

            data_inicio = datetime.datetime.strptime(
                '%04d-%02d-%02d' % (ano_atual, 1, 1),
                '%Y-%m-%d'
                )

        if not data_fim:
            data_fim = datetime.datetime.today().strftime('%Y-%m-%d')

        cabecalho = CabecalhoConsulta(
            Versao=dados.get('Versao'),
            CPFCNPJRemetente = tpCPFCNPJ(CNPJ=dados.get('CPFCNPJRemetente')),
            CPFCNPJ=tpCPFCNPJ(CNPJ=dados.get('CPFCNPJTomador')),
            Inscricao=inscr_mun_prestador,
            dtInicio=data_inicio,
            dtFim=data_fim,
            NumeroPagina=numero_pagina,
            )

        xml = self._obter_xml_da_funcao(
            xsd.PedidoConsultaNFePeriodo_v01.PedidoConsultaNFePeriodo(
                Cabecalho=cabecalho,
                Signature=SIGNATURE,
                ),
            xsd='PedidoConsultaNFePeriodo_v01')
        return self._conectar_servidor(
            xml, 'ConsultaNFePeriodo', xsd.RetornoConsulta_v01
            )

    def cancelar_nfse(self, dados):
        '''Cancelamento de NFS-e'''

        inscr_mun_prestador = int(dados.get('InscricaoPrestador'))
        numero_nfe = int(dados.get('NumeroNFe'))

        cabecalho = CabecalhoCancelamento(
            Versao=dados.get('Versao'),
            CPFCNPJRemetente=tpCPFCNPJ(CNPJ=dados.get('CPFCNPJRemetente')),
            transacao=True,
            )
        detalhe = DetalheCancelamento(
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
                Detalhe=[detalhe],
                Signature=SIGNATURE,
                ),
            True,
            xsd='PedidoCancelamentoNFe_v01'
            )
        return self._conectar_servidor(
            xml, 'CancelamentoNFe', xsd.RetornoCancelamentoNFe_v01
            )
