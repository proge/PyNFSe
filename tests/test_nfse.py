# coding: utf-8

PYSPED_PATH = '/home/daniel/devel/PySPED/'

import sys
sys.path.append('..')
sys.path.append(PYSPED_PATH)

import unittest
import datetime
from nfse.processador import ProcessadorNFSe, SIGNATURE

from nfse.nfse_xsd import *


class TestProcessadorNFSe(unittest.TestCase):

    def setUp(self):
        self.p = ProcessadorNFSe('certificado.pfx', 'senha')


    def test_enviar_lote_rps(self):
        id_rps = tcIdentificacaoRps(Numero=1, Serie=1, Tipo=1)
        data_emissao = datetime.datetime(2012, 2, 13).isoformat()
        prestador = tcIdentificacaoPrestador(Cnpj='16698062000159')
        inf_rps = tcInfRps(
            IdentificacaoRps=id_rps,
            DataEmissao=data_emissao,
            NaturezaOperacao=1,
            RegimeEspecialTributacao=1,
            OptanteSimplesNacional=True,
            IncentivadorCultural=True,
            Status=1,
            Servico=tcDadosServico(Valores=tcValores(ValorServicos=1,
                                                     ValorDeducoes=1,
                                                     ValorPis=1,
                                                     ValorCofins=1,
                                                     ValorInss=1,
                                                     ValorIr=1,
                                                     ValorCsll=1,
                                                     IssRetido=1,
                                                     ),
                                   ItemListaServico=1,
                                   CodigoCnae=1,
                                   CodigoTributacaoMunicipio=1,
                                   Discriminacao=1,
                                   CodigoMunicipio=1,
                                   ),
            Prestador=prestador
            )
        rps = Rps=[tcRps(InfRps=inf_rps, Signature=SIGNATURE)]

        lote_rps = tcLoteRps(NumeroLote=1,
                             Cnpj='16698062000159',
                             InscricaoMunicipal=1, 
                             QuantidadeRps=1, 
                             ListaRps=ListaRpsType(rps)
                             )
        codigo, titulo, conteudo = self.p.enviar_lote_rps(lote_rps)
        print codigo, '-', titulo


    def test_consultar_situacao_lote_rps(self):
        prestador = tcIdentificacaoPrestador(Cnpj='16698062000159')
        protocolo = 1
        codigo, titulo, conteudo = self.p.consultar_situacao_lote_rps(prestador, protocolo)
        print codigo, '-', titulo
        self.assertEqual(codigo, 403)


    def test_consultar_nfse_por_rps(self):
        identificacao_rps = tcIdentificacaoRps(Numero=1, Serie=1, Tipo=1)
        prestador = tcIdentificacaoPrestador(Cnpj='16698062000159')
        codigo, titulo, conteudo = self.p.consultar_nfse_por_rps(identificacao_rps, prestador)
        print codigo, '-', titulo
        self.assertEqual(codigo, 403)


    def test_consultar_lote_rps(self):
        prestador = tcIdentificacaoPrestador(Cnpj='16698062000159')
        protocolo = 1
        codigo, titulo, conteudo = self.p.consultar_lote_rps(prestador, protocolo)
        print codigo, '-', titulo
        self.assertEqual(codigo, 403)
    
    
    def test_consultar_nfse(self):
        prestador = tcIdentificacaoPrestador(Cnpj='16698062000159')
        numero_nfse = 1
        data_inicial = datetime.date(2012, 2, 13).isoformat()
        data_final = datetime.date(2012, 10, 13).isoformat()
        periodo_emissao = PeriodoEmissaoType(DataInicial=data_inicial,
                                             DataFinal=data_final)
        cpf_cnpj = tcCpfCnpj(Cpf='11111111111')
        tomador = tcIdentificacaoTomador(CpfCnpj=cpf_cnpj,
                                         InscricaoMunicipal=2)
        intermediario = tcIdentificacaoIntermediarioServico(RazaoSocial='A',
                                                            CpfCnpj=cpf_cnpj,
                                                            InscricaoMunicipal=3
                                                            )
        codigo, titulo, conteudo = self.p.consultar_nfse(prestador, 
                                                         numero_nfse, 
                                                         periodo_emissao, 
                                                         tomador, 
                                                         intermediario)
        print codigo, '-', titulo
        self.assertEqual(codigo, 403)


    def test_cancelar_nfse(self):
        nfse = tcIdentificacaoNfse(Numero=1, Cnpj='16698062000159', InscricaoMunicipal=1, CodigoMunicipio=1)
        inf_pedido_cancelamento = tcInfPedidoCancelamento(IdentificacaoNfse=nfse, CodigoCancelamento='E64')
    
        pedido = tcPedidoCancelamento(InfPedidoCancelamento=inf_pedido_cancelamento,
                                      Signature=SIGNATURE)
        
        codigo, titulo, conteudo = self.p.cancelar_nfse(pedido)
        print codigo, '-', titulo
        self.assertEqual(codigo, 403)


if __name__ == '__main__':
    unittest.main()
