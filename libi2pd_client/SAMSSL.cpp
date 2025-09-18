/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cstdio>
#include <sstream>
#include <iomanip>
#include <openssl/x509.h>
#include <openssl/pem.h>

// Use global placeholders from boost introduced when local_time.hpp is loaded
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include "FS.h"
#include "Log.h"
#include "Config.h"
#include "SAMSSL.h"

namespace i2p
{
namespace client
{
	SAMSslTerminator::SAMSslTerminator (const std::string& listenAddress, uint16_t listenPort,
		const std::string& backendAddress, uint16_t backendPort,
		const std::string& certFile, const std::string& keyFile):
		m_IsRunning (false),
		m_SSLContext (boost::asio::ssl::context::sslv23),
		m_BackendEndpoint (boost::asio::ip::make_address(backendAddress), backendPort),
		m_CertFile (certFile), m_KeyFile (keyFile)
	{
		if (listenPort)
			m_Acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(m_Service,
				boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(listenAddress), listenPort));

		// prepare certs
		std::string crt = m_CertFile; if (crt.size() && crt.at(0) != '/') crt = i2p::fs::DataDirPath(crt);
		std::string key = m_KeyFile; if (key.size() && key.at(0) != '/') key = i2p::fs::DataDirPath(key);
		m_CertFile = crt; m_KeyFile = key;
		CreateCertificateIfMissing (m_CertFile, m_KeyFile);
		m_SSLContext.set_options (boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use);
		boost::system::error_code ec;
		m_SSLContext.use_certificate_file (m_CertFile, boost::asio::ssl::context::pem, ec);
		if (!ec)
			m_SSLContext.use_private_key_file (m_KeyFile, boost::asio::ssl::context::pem, ec);
		if (ec)
		{
			LogPrint (eLogCritical, "SAMSSL: Failed to load certificate: ", ec.message());
			throw std::runtime_error("SAMSSL: Failed to load certificate");
		}
	}

	SAMSslTerminator::~SAMSslTerminator ()
	{
		Stop ();
	}

	void SAMSslTerminator::Start ()
	{
		if (!m_Acceptor) return;
		m_IsRunning = true;
		m_Acceptor->listen ();
		Accept ();
		m_Thread.reset (new std::thread ([this]() {
			while (m_IsRunning)
			{
				try
				{
					m_Service.run ();
				}
				catch (std::exception& ex)
				{
					LogPrint (eLogError, "SAMSSL: Runtime exception: ", ex.what());
				}
				m_Service.restart ();
			}
		}));
	}

	void SAMSslTerminator::Stop ()
	{
		if (!m_IsRunning) return;
		m_IsRunning = false;
		if (m_Acceptor)
		{
			boost::system::error_code ec;
			m_Acceptor->cancel (ec);
			m_Acceptor->close (ec);
		}
		m_Service.stop ();
		if (m_Thread)
		{
			m_Thread->join ();
			m_Thread = nullptr;
		}
	}

	void SAMSslTerminator::Accept ()
	{
		auto newSocket = std::make_shared<ssl_socket_t> (m_Service, m_SSLContext);
		m_Acceptor->async_accept (newSocket->lowest_layer(),
			[this, newSocket](const boost::system::error_code& ecode)
			{
				HandleAccepted (ecode, newSocket);
			});
	}

	template<typename Socket>
	void SAMSslTerminator::HandleAccepted (const boost::system::error_code& ecode, std::shared_ptr<Socket> newSocket)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
		if (ecode)
		{
			LogPrint (eLogError, "SAMSSL: Accept error: ", ecode.message());
			return;
		}
		Handshake (newSocket);
	}

	void SAMSslTerminator::Handshake (std::shared_ptr<ssl_socket_t> socket)
	{
		socket->async_handshake(boost::asio::ssl::stream_base::server,
			[this, socket](const boost::system::error_code& ecode)
			{
				if (ecode)
				{
					LogPrint (eLogError, "SAMSSL: Handshake error: ", ecode.message());
					return;
				}
				LogPrint (eLogDebug, "SAMSSL: Handshake OK");
				ConnectBackend (socket);
			});
	}

	void SAMSslTerminator::ConnectBackend (std::shared_ptr<ssl_socket_t> frontend)
	{
		auto backend = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
		backend->async_connect (m_BackendEndpoint, [this, frontend, backend](const boost::system::error_code& ecode)
		{
			if (ecode)
			{
				LogPrint (eLogError, "SAMSSL: Backend connect error: ", ecode.message());
				boost::system::error_code ignored;
				frontend->lowest_layer().shutdown (boost::asio::ip::tcp::socket::shutdown_both, ignored);
				frontend->lowest_layer().close (ignored);
				return;
			}
			LogPrint (eLogDebug, "SAMSSL: Backend connected to ", m_BackendEndpoint);
			struct Bridge : public std::enable_shared_from_this<Bridge>
			{
				std::shared_ptr<ssl_socket_t> front;
				std::shared_ptr<boost::asio::ip::tcp::socket> back;
				std::array<uint8_t, 8192> f2b{};
				std::array<uint8_t, 8192> b2f{};

				static std::shared_ptr<Bridge> create(std::shared_ptr<ssl_socket_t> f, std::shared_ptr<boost::asio::ip::tcp::socket> b)
				{
					auto s = std::make_shared<Bridge>();
					s->front = std::move(f);
					s->back = std::move(b);
					return s;
				}

				void start()
				{
					read_front();
					read_back();
				}

				void shutdown()
				{
					boost::system::error_code ec;
					if (front)
					{
						front->lowest_layer().shutdown (boost::asio::ip::tcp::socket::shutdown_both, ec);
						front->lowest_layer().close (ec);
					}
					if (back)
					{
						back->shutdown (boost::asio::ip::tcp::socket::shutdown_both, ec);
						back->close (ec);
					}
				}

				void read_front()
				{
					auto self = shared_from_this();
					front->async_read_some (boost::asio::buffer(f2b),
						[self](const boost::system::error_code& re, std::size_t n)
						{
							if (re)
							{
								self->shutdown();
								return;
							}
							boost::asio::async_write (*self->back, boost::asio::buffer(self->f2b.data(), n), boost::asio::transfer_all(),
								[self, n](const boost::system::error_code& we, std::size_t written)
								{
									if (we)
									{
										self->shutdown();
										return;
									}
									LogPrint (eLogDebug, "SAMSSL: fwd TLS->SAM ", (int)written, "/", (int)n, " bytes");
									self->read_front();
								});
						});
				}

				void read_back()
				{
					auto self = shared_from_this();
					back->async_read_some (boost::asio::buffer(b2f),
						[self](const boost::system::error_code& re, std::size_t n)
						{
							if (re)
							{
								self->shutdown();
								return;
							}
							boost::asio::async_write (*self->front, boost::asio::buffer(self->b2f.data(), n), boost::asio::transfer_all(),
								[self, n](const boost::system::error_code& we, std::size_t written)
								{
									if (we)
									{
										self->shutdown();
										return;
									}
									LogPrint (eLogDebug, "SAMSSL: fwd SAM->TLS ", (int)written, "/", (int)n, " bytes");
									self->read_back();
								});
						});
				}
			};
			auto bridge = Bridge::create (frontend, backend);
			bridge->start();
		});
	}

	void SAMSslTerminator::CreateCertificateIfMissing (const std::string& crt_path, const std::string& key_path)
	{
		if (i2p::fs::Exists (crt_path) && i2p::fs::Exists (key_path)) return;
		LogPrint (eLogInfo, "SAMSSL: Creating new certificate for SAM over SSL");
		FILE *f = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x030000000)
		EVP_PKEY *  pkey = EVP_RSA_gen(2048);
#else
		EVP_PKEY * pkey = EVP_PKEY_new ();
		RSA * rsa = RSA_new ();
		BIGNUM * e = BN_new(); BN_set_word(e, RSA_F4);
		RSA_generate_key_ex (rsa, 2048, e, NULL);
		BN_free (e);
		if (rsa) EVP_PKEY_assign_RSA (pkey, rsa);
#endif
		X509 * x509 = X509_new ();
		ASN1_INTEGER_set (X509_get_serialNumber (x509), 1);
		X509_gmtime_adj (X509_getm_notBefore (x509), 0);
		X509_gmtime_adj (X509_getm_notAfter (x509), 3650*24*60*60); // ~10 years
		X509_set_pubkey (x509, pkey);
		X509_NAME * name = X509_get_subject_name (x509);
		X509_NAME_add_entry_by_txt (name, "C",  MBSTRING_ASC, (unsigned char *)"A1", -1, -1, 0);
		X509_NAME_add_entry_by_txt (name, "O",  MBSTRING_ASC, (unsigned char *)"i2pd", -1, -1, 0);
		X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_ASC, (unsigned char *)"i2pd-sam", -1, -1, 0);
		X509_set_issuer_name (x509, name);
		X509_sign (x509, pkey, EVP_sha1 ());
		if ((f = fopen (crt_path.c_str(), "wb")) != NULL)
		{
			PEM_write_X509 (f, x509); fclose (f);
		}
		if ((f = fopen (key_path.c_str(), "wb")) != NULL)
		{
			PEM_write_PrivateKey (f, pkey, NULL, NULL, 0, NULL, NULL); fclose (f);
		}
		X509_free (x509);
		EVP_PKEY_free (pkey);
	}

}
}


