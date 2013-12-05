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
import re
from .processador_base import ProcessadorBase
from . import nfse_xsd as xsd

CIDADES = {
    '04557': {
        'servidor': 'notacarioca.rio.gov.br',
        'servidor_homologacao': 'homologacao.notacarioca.rio.gov.br',
        'endereco': '/WSNacional/nfse.asmx',
        }
    }

# Classe herdada por que assinatura requer um namespace específico
class Signature(xsd.SignatureType):
    def export(self, outfile, level, namespace_='', name_='SignatureType', namespacedef_='xmlns="http://www.w3.org/2000/09/xmldsig#"', pretty_print=True):
        xsd.SignatureType.export(self, outfile, level, namespace_=namespace_, name_=name_, namespacedef_=namespacedef_)

class Base64Binary(xsd.GeneratedsSuper):
    def __init__(self, name='', value=''):
        self.name = name
        self.value = value
    def export(self, outfile, level, namespace_='', name_='DigestValueType', namespacedef_='', pretty_print=True):
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
    def __init__(self, codigo_cidade, certificado, senha, caminho=''):

        cidade = CIDADES.get(codigo_cidade)

        if not cidade:
            raise Exception(u'NFS-e da cidade da empresa não é suportada pelo sistema.')
        
        super(ProcessadorNFSe, self).__init__(
            cidade.get('servidor'),
            cidade.get('endereco'),
            certificado,
            senha,
            caminho,
            cidade.get('servidor_homologacao'),
            )

        SIGNATURE.KeyInfo = xsd.KeyInfoType(X509Data=xsd.X509DataType(
                X509Certificate=self._certificado.certificado_txt
                )
            )

    def _gerar_xml_envio(self, lote_rps):
        rps_obj_list = []

        for rps in lote_rps:
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
                #ValorIss=rps.get(''),
                #ValorIssRetido=rps.get(''),
                #OutrasRetencoes=rps.get(''),
                #BaseCalculo=rps.get(''),
                Aliquota=rps.get('AliquotaServicos'),
                #ValorLiquidoNfse=rps.get('ValorServicos'),
                #DescontoIncondicionado=rps.get(''),
                #DescontoCondicionado=rps.get('')
                )
                
            _Servico=xsd.tcDadosServico(
                Valores=_Valores,
                ItemListaServico=rps.get('ItemListaServico'),
                #CodigoCnae=rps.get(''),
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
                #Telefone=rps.get(''),
                Email=rps.get('EmailTomador')
                )

            _Tomador=xsd.tcDadosTomador(
                IdentificacaoTomador=_IdentificacaoTomador,
                RazaoSocial=rps.get('RazaoSocialTomador'),
                Endereco=_Endereco,
                Contato=_Contato
                )
        
            _InfRps=xsd.tcInfRps(
                IdentificacaoRps=_IdentificacaoRps,
                DataEmissao=data_emissao,
                NaturezaOperacao=1,#TODO TributacaoRPS?
                OptanteSimplesNacional=2, #TODO 1-sim,2-nao
                IncentivadorCultural=2, #TODO
                Status=1,#TODO 1-normal,2-cancelado
                Servico=_Servico,
                Prestador=_Prestador,
                Tomador=_Tomador
                )

            rps_obj = xsd.tcRps(
                InfRps=_InfRps
                )

            rps_obj_list.append(rps_obj)
       
        lote_rps_obj = xsd.tcLoteRps(
            NumeroLote=rps.get('NumeroLote'),
            Cnpj=rps.get('CNPJPrestador'),
            InscricaoMunicipal=rps.get('InscricaoMunicipalPrestador'),
            QuantidadeRps=len(rps_obj_list),
            ListaRps=xsd.ListaRpsType(Rps=rps_obj_list)
            )

        return self._obter_xml_da_funcao(
            xsd.EnviarLoteRpsEnvio(
                LoteRps=lote_rps_obj,
                Signature=SIGNATURE
                ),
            True,
            xsd='EnviarLoteRpsEnvio'
            )

    def enviar_lote_rps(self, lote_rps, test=False):
        '''Recepção e Processamento de Lote de RPS'''
        xml = self._gerar_xml_envio(lote_rps)
        return self._conectar_servidor(xml, 'RecepcionarLoteRps', xsd.EnviarLoteRpsResposta, test)

    def consultar_situacao_lote_rps(self, prestador, protocolo):
        '''Consulta de Situação de Lote de RPS'''
        xml = self._obter_xml_da_funcao(
            xsd.ConsultarSituacaoLoteRpsEnvio(Prestador=prestador,
                                              Protocolo=protocolo)
            )
        return self._conectar_servidor(xml, 'ConsultarSituacaoLoteRps', xsd.ConsultarSituacaoLoteRpsResposta)

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
        return self._conectar_servidor(xml, 'ConsultarLoteRps', xsd.ConsultarLoteRpsResposta)

    def consultar_nfse(self, prestador, numero_nfse, periodo_emissao, tomador, intermediario_servico):
        '''Consulta de NFS-e'''
        xml = self._obter_xml_da_funcao(
            xsd.ConsultarNfseEnvio(Prestador=prestador,
                                   NumeroNfse=numero_nfse,
                                   PeriodoEmissao=periodo_emissao,
                                   Tomador=tomador,
                                   IntermediarioServico=intermediario_servico)
            )
        return self._conectar_servidor(xml, 'ConsultarNfse', xsd.ConsultarNfseResposta)

    def cancelar_nfse(self, pedido):
        '''Cancelamento de NFS-e'''
        xml = self._obter_xml_da_funcao(
            xsd.CancelarNfseEnvio(Pedido=pedido), True
            )
        return self._conectar_servidor(xml, 'CancelarNfse', xsd.CancelarNfseResposta)
