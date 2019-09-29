// Compiles with Visual Studio 2008 for Windows

// This C example is designed as more of a guide than a library to be plugged into an application
// That module required a couple of major re-writes and is available upon request
// The Basic example has tips to the direction you should take
// This will work with connections on port 587 that upgrade a plain text session to an encrypted session with STARTTLS as covered here.

// TLSclient.c - SSPI Schannel gmail TLS connection example

#define SECURITY_WIN32
#define IO_BUFFER_SIZE  0x10000
#define NT4_DLL_NAME TEXT("Security.dll")

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <string>
#include <array>
#include <vector>

#pragma comment(lib, "WSock32.Lib")
#pragma comment(lib, "Crypt32.Lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "MSVCRTD.lib")

// Globals.

LPSTR	pszUser = 0; // if specified, a certificate in "MY" store is searched for

DWORD	dwProtocol = SP_PROT_TLS1; // SP_PROT_TLS1; // SP_PROT_PCT1; SP_PROT_SSL2; SP_PROT_SSL3; 0=default
ALG_ID	aiKeyExch = 0; // = default; CALG_DH_EPHEM; CALG_RSA_KEYX;

HCERTSTORE hMyCertStore = NULL;
HMODULE g_hSecurity = NULL;

SCHANNEL_CRED SchannelCred;
PSecurityFunctionTableW g_pSSPI;

namespace PVX {
	namespace Network {

		bool LoadSecurityLibrary(void) {
			INIT_SECURITY_INTERFACE_W pInitSecurityInterface;
			g_hSecurity = LoadLibrary("Secur32.dll");
			pInitSecurityInterface = (INIT_SECURITY_INTERFACE_W)GetProcAddress(g_hSecurity, "InitSecurityInterfaceW");
			g_pSSPI = pInitSecurityInterface();
			return true;
		}

		/*****************************************************************************/
		static std::string DisplayWinVerifyTrustError(DWORD Status) {
			switch (Status) {
				case CERT_E_EXPIRED:                return "CERT_E_EXPIRED";
				case CERT_E_VALIDITYPERIODNESTING:  return "CERT_E_VALIDITYPERIODNESTING";
				case CERT_E_ROLE:                   return "CERT_E_ROLE";
				case CERT_E_PATHLENCONST:           return "CERT_E_PATHLENCONST";
				case CERT_E_CRITICAL:               return "CERT_E_CRITICAL";
				case CERT_E_PURPOSE:                return "CERT_E_PURPOSE";
				case CERT_E_ISSUERCHAINING:         return "CERT_E_ISSUERCHAINING";
				case CERT_E_MALFORMED:              return "CERT_E_MALFORMED";
				case CERT_E_UNTRUSTEDROOT:          return "CERT_E_UNTRUSTEDROOT";
				case CERT_E_CHAINING:               return "CERT_E_CHAINING";
				case TRUST_E_FAIL:                  return "TRUST_E_FAIL";
				case CERT_E_REVOKED:                return "CERT_E_REVOKED";
				case CERT_E_UNTRUSTEDTESTROOT:      return "CERT_E_UNTRUSTEDTESTROOT";
				case CERT_E_REVOCATION_FAILURE:     return "CERT_E_REVOCATION_FAILURE";
				case CERT_E_CN_NO_MATCH:            return "CERT_E_CN_NO_MATCH";
				case CERT_E_WRONG_USAGE:            return "CERT_E_WRONG_USAGE";
				default:                            return "(unknown)";
			}
		}

		/*****************************************************************************/
		static void DisplayWinSockError(DWORD ErrCode) {
			const char* pszName = [](DWORD ErrCode) {
				switch (ErrCode) // http://msdn.microsoft.com/en-us/library/ms740668(VS.85).aspx
				{
					case 10035:  return "WSAEWOULDBLOCK    ";
					case 10036:  return "WSAEINPROGRESS    ";
					case 10037:  return "WSAEALREADY       ";
					case 10038:  return "WSAENOTSOCK       ";
					case 10039:  return "WSAEDESTADDRREQ   ";
					case 10040:  return "WSAEMSGSIZE       ";
					case 10041:  return "WSAEPROTOTYPE     ";
					case 10042:  return "WSAENOPROTOOPT    ";
					case 10043:  return "WSAEPROTONOSUPPORT";
					case 10044:  return "WSAESOCKTNOSUPPORT";
					case 10045:  return "WSAEOPNOTSUPP     ";
					case 10046:  return "WSAEPFNOSUPPORT   ";
					case 10047:  return "WSAEAFNOSUPPORT   ";
					case 10048:  return "WSAEADDRINUSE     ";
					case 10049:  return "WSAEADDRNOTAVAIL  ";
					case 10050:  return "WSAENETDOWN       ";
					case 10051:  return "WSAENETUNREACH    ";
					case 10052:  return "WSAENETRESET      ";
					case 10053:  return "WSAECONNABORTED   ";
					case 10054:  return "WSAECONNRESET     ";
					case 10055:  return "WSAENOBUFS        ";
					case 10056:  return "WSAEISCONN        ";
					case 10057:  return "WSAENOTCONN       ";
					case 10058:  return "WSAESHUTDOWN      ";
					case 10059:  return "WSAETOOMANYREFS   ";
					case 10060:  return "WSAETIMEDOUT      ";
					case 10061:  return "WSAECONNREFUSED   ";
					case 10062:  return "WSAELOOP          ";
					case 10063:  return "WSAENAMETOOLONG   ";
					case 10064:  return "WSAEHOSTDOWN      ";
					case 10065:  return "WSAEHOSTUNREACH   ";
					case 10066:  return "WSAENOTEMPTY      ";
					case 10067:  return "WSAEPROCLIM       ";
					case 10068:  return "WSAEUSERS         ";
					case 10069:  return "WSAEDQUOT         ";
					case 10070:  return "WSAESTALE         ";
					case 10071:  return "WSAEREMOTE        ";
					case 10091:  return "WSASYSNOTREADY    ";
					case 10092:  return "WSAVERNOTSUPPORTED";
					case 10093:  return "WSANOTINITIALISED ";
					case 11001:  return "WSAHOST_NOT_FOUND ";
					case 11002:  return "WSATRY_AGAIN      ";
					case 11003:  return "WSANO_RECOVERY    ";
					case 11004:  return "WSANO_DATA        ";
				}
			}(ErrCode);

			
			printf("Error 0x%x (%s)\n", ErrCode, pszName);
		}

		/*****************************************************************************/
		std::string DisplaySECError(DWORD ErrCode) {
			switch (ErrCode) {
				case SEC_E_BUFFER_TOO_SMALL: return "SEC_E_BUFFER_TOO_SMALL - The message buffer is too small. Used with the Digest SSP.";
				case SEC_E_CRYPTO_SYSTEM_INVALID: return "SEC_E_CRYPTO_SYSTEM_INVALID - The cipher chosen for the security context is not supported. Used with the Digest SSP.";
				case SEC_E_INCOMPLETE_MESSAGE: return "SEC_E_INCOMPLETE_MESSAGE - The data in the input buffer is incomplete. The application needs to read more data from the server and call DecryptMessage (General) again.";
				case SEC_E_INVALID_HANDLE: return "SEC_E_INVALID_HANDLE - A context handle that is not valid was specified in the phContext parameter. Used with the Digest and Schannel SSPs.";
				case SEC_E_INVALID_TOKEN: return "SEC_E_INVALID_TOKEN - The buffers are of the wrong type or no buffer of type SECBUFFER_DATA was found. Used with the Schannel SSP.";
				case SEC_E_MESSAGE_ALTERED: return "SEC_E_MESSAGE_ALTERED - The message has been altered. Used with the Digest and Schannel SSPs.";
				case SEC_E_OUT_OF_SEQUENCE: return "SEC_E_OUT_OF_SEQUENCE - The message was not received in the correct sequence.";
				case SEC_E_QOP_NOT_SUPPORTED: return "SEC_E_QOP_NOT_SUPPORTED - Neither confidentiality nor integrity are supported by the security context. Used with the Digest SSP.";
				case SEC_I_CONTEXT_EXPIRED: return "SEC_I_CONTEXT_EXPIRED - The message sender has finished using the connection and has initiated a shutdown.";
				case SEC_I_RENEGOTIATE: return "SEC_I_RENEGOTIATE - The remote party requires a new handshake sequence or the application has just initiated a shutdown.";
				case SEC_E_ENCRYPT_FAILURE: return "SEC_E_ENCRYPT_FAILURE - The specified data could not be encrypted.";
				case SEC_E_DECRYPT_FAILURE: return "SEC_E_DECRYPT_FAILURE - The specified data could not be decrypted.";
			}
		}

		/*****************************************************************************/
		static void DisplayCertChain(PCCERT_CONTEXT  pServerCert, BOOL fLocal) {
			CHAR szName[1000];
			PCCERT_CONTEXT pCurrentCert, pIssuerCert;
			DWORD dwVerificationFlags;

			printf("\n");

			// display leaf name
			if (!CertNameToStr(pServerCert->dwCertEncodingType,
				&pServerCert->pCertInfo->Subject,
				CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
				szName, sizeof(szName))) {
				printf("**** Error 0x%x building subject name\n", GetLastError());
			}

			if (fLocal) printf("Client subject: %s\n", szName);
			else printf("Server subject: %s\n", szName);

			if (!CertNameToStr(pServerCert->dwCertEncodingType,
				&pServerCert->pCertInfo->Issuer,
				CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
				szName, sizeof(szName))) {
				printf("**** Error 0x%x building issuer name\n", GetLastError());
			}

			if (fLocal) printf("Client issuer: %s\n", szName);
			else printf("Server issuer: %s\n\n", szName);


			// display certificate chain
			pCurrentCert = pServerCert;
			while (pCurrentCert != NULL) {
				dwVerificationFlags = 0;
				pIssuerCert = CertGetIssuerCertificateFromStore(pServerCert->hCertStore, pCurrentCert, NULL, &dwVerificationFlags);
				if (pIssuerCert == NULL) {
					if (pCurrentCert != pServerCert) CertFreeCertificateContext(pCurrentCert);
					break;
				}

				if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
					&pIssuerCert->pCertInfo->Subject,
					CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
					szName, sizeof(szName))) {
					printf("**** Error 0x%x building subject name\n", GetLastError());
				}

				printf("CA subject: %s\n", szName);

				if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
					&pIssuerCert->pCertInfo->Issuer,
					CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
					szName, sizeof(szName))) {
					printf("**** Error 0x%x building issuer name\n", GetLastError());
				}

				printf("CA issuer: %s\n\n", szName);

				if (pCurrentCert != pServerCert) CertFreeCertificateContext(pCurrentCert);
				pCurrentCert = pIssuerCert;
				pIssuerCert = NULL;
			}
		}

		/*****************************************************************************/
		static void DisplayConnectionInfo(CtxtHandle* phContext) {

			SECURITY_STATUS Status;
			SecPkgContext_ConnectionInfo ConnectionInfo;

			Status = g_pSSPI->QueryContextAttributesW(phContext, SECPKG_ATTR_CONNECTION_INFO, (PVOID)&ConnectionInfo);

			switch (ConnectionInfo.dwProtocol) {
				case SP_PROT_TLS1_CLIENT:
					printf("Protocol: TLS1\n");
					break;

				case SP_PROT_SSL3_CLIENT:
					printf("Protocol: SSL3\n");
					break;

				case SP_PROT_PCT1_CLIENT:
					printf("Protocol: PCT\n");
					break;

				case SP_PROT_SSL2_CLIENT:
					printf("Protocol: SSL2\n");
					break;

				default:
					printf("Protocol: 0x%x\n", ConnectionInfo.dwProtocol);
			}

			switch (ConnectionInfo.aiCipher) {
				case CALG_RC4:
					printf("Cipher: RC4\n");
					break;

				case CALG_3DES:
					printf("Cipher: Triple DES\n");
					break;

				case CALG_RC2:
					printf("Cipher: RC2\n");
					break;

				case CALG_DES:
				case CALG_CYLINK_MEK:
					printf("Cipher: DES\n");
					break;

				case CALG_SKIPJACK:
					printf("Cipher: Skipjack\n");
					break;

				default:
					printf("Cipher: 0x%x\n", ConnectionInfo.aiCipher);
			}

			printf("Cipher strength: %d\n", ConnectionInfo.dwCipherStrength);

			switch (ConnectionInfo.aiHash) {
				case CALG_MD5:
					printf("Hash: MD5\n");
					break;

				case CALG_SHA:
					printf("Hash: SHA\n");
					break;

				default:
					printf("Hash: 0x%x\n", ConnectionInfo.aiHash);
			}

			printf("Hash strength: %d\n", ConnectionInfo.dwHashStrength);

			switch (ConnectionInfo.aiExch) {
				case CALG_RSA_KEYX:
				case CALG_RSA_SIGN:
					printf("Key exchange: RSA\n");
					break;

				case CALG_KEA_KEYX:
					printf("Key exchange: KEA\n");
					break;

				case CALG_DH_EPHEM:
					printf("Key exchange: DH Ephemeral\n");
					break;

				default:
					printf("Key exchange: 0x%x\n", ConnectionInfo.aiExch);
			}

			printf("Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
		}

		/*****************************************************************************/
		static void PrintText(DWORD length, PBYTE buffer) // handle unprintable charaters
		{
			int i; //

			printf("\n"); // "length = %d bytes \n", length);
			for (i = 0; i < (int)length; i++) {
				if (buffer[i] == 10 || buffer[i] == 13)
					printf("%c", (char)buffer[i]);
				else if (buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%')
					printf("%c", '.');
				else
					printf("%c", (char)buffer[i]);
			}
			printf("\n");
		}

		/*****************************************************************************/
		void UnloadSecurityLibrary(void) {
			FreeLibrary(g_hSecurity);
			g_hSecurity = NULL;
		}

		/*****************************************************************************/
		static DWORD VerifyServerCertificate(PCCERT_CONTEXT pServerCert, std::wstring ServerName, DWORD dwCertFlags) {
			HTTPSPolicyCallbackData  polHttps;
			CERT_CHAIN_POLICY_PARA   PolicyPara;
			CERT_CHAIN_POLICY_STATUS PolicyStatus;
			CERT_CHAIN_PARA          ChainPara{};
			PCCERT_CHAIN_CONTEXT     pChainContext = NULL;
			DWORD                    Status;

			
			LPSTR rgszUsages[] = { 
				(LPSTR)szOID_PKIX_KP_SERVER_AUTH,
				(LPSTR)szOID_SERVER_GATED_CRYPTO,
				(LPSTR)szOID_SGC_NETSCAPE
			};

			DWORD cUsages = sizeof(rgszUsages) / sizeof(LPSTR);

			if (pServerCert == NULL) { Status = SEC_E_WRONG_PRINCIPAL; goto cleanup; }

			// Build certificate chain.
			ChainPara.cbSize = sizeof(ChainPara);
			ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
			ChainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
			ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

			if (!CertGetCertificateChain(NULL,
				pServerCert,
				NULL,
				pServerCert->hCertStore,
				&ChainPara,
				0,
				NULL,
				&pChainContext)) {
				Status = GetLastError();
				printf("Error 0x%x returned by CertGetCertificateChain!\n", Status);
				goto cleanup;
			}


			// Validate certificate chain.
			ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
			polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
			polHttps.dwAuthType = AUTHTYPE_SERVER;
			polHttps.fdwChecks = dwCertFlags;
			polHttps.pwszServerName = &ServerName[0];

			memset(&PolicyPara, 0, sizeof(PolicyPara));
			PolicyPara.cbSize = sizeof(PolicyPara);
			PolicyPara.pvExtraPolicyPara = &polHttps;

			memset(&PolicyStatus, 0, sizeof(PolicyStatus));
			PolicyStatus.cbSize = sizeof(PolicyStatus);

			if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
				pChainContext,
				&PolicyPara,
				&PolicyStatus)) {
				Status = GetLastError();
				printf("Error 0x%x returned by CertVerifyCertificateChainPolicy!\n", Status);
				goto cleanup;
			}

			if (PolicyStatus.dwError) {
				Status = PolicyStatus.dwError;
				DisplayWinVerifyTrustError(Status);
				goto cleanup;
			}

			Status = SEC_E_OK;

		cleanup:
			if (pChainContext)  CertFreeCertificateChain(pChainContext);
			return Status;
		}

		/*****************************************************************************/
		static SECURITY_STATUS CreateCredentials(LPSTR pszUser, PCredHandle phCreds) { //                                                in                     out
			TimeStamp        tsExpiry;
			SECURITY_STATUS  Status;
			DWORD            cSupportedAlgs = 0;
			ALG_ID           rgbSupportedAlgs[16];
			PCCERT_CONTEXT   pCertContext = NULL;

			// Open the "MY" certificate store, where IE stores client certificates.
				// Windows maintains 4 stores -- MY, CA, ROOT, SPC.
			if (hMyCertStore == NULL) {
				hMyCertStore = CertOpenSystemStore(0, "MY");
				if (!hMyCertStore) {
					printf("**** Error 0x%x returned by CertOpenSystemStore\n", GetLastError());
					return SEC_E_NO_CREDENTIALS;
				}
			}

			// If a user name is specified, then attempt to find a client
			// certificate. Otherwise, just create a NULL credential.
			if (pszUser) {
				// Find client certificate. Note that this sample just searches for a
				// certificate that contains the user name somewhere in the subject name.
				// A real application should be a bit less casual.
				pCertContext = CertFindCertificateInStore(hMyCertStore,                     // hCertStore
														   X509_ASN_ENCODING,             // dwCertEncodingType
														   0,                                             // dwFindFlags
														   CERT_FIND_SUBJECT_STR_A,// dwFindType
														   pszUser,                         // *pvFindPara
														   NULL);                                 // pPrevCertContext


				if (pCertContext == NULL) {
					printf("**** Error 0x%x returned by CertFindCertificateInStore\n", GetLastError());
					if (GetLastError() == CRYPT_E_NOT_FOUND) printf("CRYPT_E_NOT_FOUND - property doesn't exist\n");
					return SEC_E_NO_CREDENTIALS;
				}
			}

			// Build Schannel credential structure. Currently, this sample only
			// specifies the protocol to be used (and optionally the certificate,
			// of course). Real applications may wish to specify other parameters as well.
			ZeroMemory(&SchannelCred, sizeof(SchannelCred));

			SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
			if (pCertContext) {
				SchannelCred.cCreds = 1;
				SchannelCred.paCred = &pCertContext;
			}

			SchannelCred.grbitEnabledProtocols = dwProtocol;

			if (aiKeyExch) rgbSupportedAlgs[cSupportedAlgs++] = aiKeyExch;

			if (cSupportedAlgs) {
				SchannelCred.cSupportedAlgs = cSupportedAlgs;
				SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
			}

			SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;

			// The SCH_CRED_MANUAL_CRED_VALIDATION flag is specified because
			// this sample verifies the server certificate manually.
			// Applications that expect to run on WinNT, Win9x, or WinME
			// should specify this flag and also manually verify the server
			// certificate. Applications running on newer versions of Windows can
			// leave off this flag, in which case the InitializeSecurityContext
			// function will validate the server certificate automatically.
			SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;


			// Create an SSPI credential.
			Status = g_pSSPI->AcquireCredentialsHandleW(0, (SEC_WCHAR*)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, 0, &SchannelCred, 0, 0, phCreds, &tsExpiry); // (out) Lifetime (optional)

			if (Status != SEC_E_OK) printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);

			// cleanup: Free the certificate context. Schannel has already made its own copy.
			if (pCertContext) CertFreeCertificateContext(pCertContext);

			return Status;
		}

		/*****************************************************************************/
		static INT ConnectToServer(const char* pszServerName, INT iPortNumber, SOCKET* pSocket) { //                                    in                in                 out
			SOCKET Socket;
			struct sockaddr_in sin;
			struct hostent* hp;


			Socket = socket(PF_INET, SOCK_STREAM, 0);
			if (Socket == INVALID_SOCKET) {
				printf("**** Error %d creating socket\n", WSAGetLastError());
				DisplayWinSockError(WSAGetLastError());
				return WSAGetLastError();
			}


			else // No proxy used
			{
				sin.sin_family = AF_INET;
				sin.sin_port = htons((u_short)iPortNumber);
				if ((hp = gethostbyname(pszServerName)) == NULL) {
					printf("**** Error returned by gethostbyname\n");
					DisplayWinSockError(WSAGetLastError());
					return WSAGetLastError();
				} else
					memcpy(&sin.sin_addr, hp->h_addr, 4);
			}


			if (connect(Socket, (struct sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) {
				printf("**** Error %d connecting to \"%s\" (%s)\n", WSAGetLastError(), pszServerName, inet_ntoa(sin.sin_addr));
				closesocket(Socket);
				DisplayWinSockError(WSAGetLastError());
				return WSAGetLastError();
			}


			*pSocket = Socket;

			return SEC_E_OK;
		}

		/*****************************************************************************/
		static LONG DisconnectFromServer(SOCKET Socket, PCredHandle phCreds, CtxtHandle* phContext) {
			PBYTE                    pbMessage;
			DWORD                    dwType, dwSSPIFlags, dwSSPIOutFlags, cbMessage, cbData, Status;
			SecBufferDesc OutBuffer;
			SecBuffer     OutBuffers[1];
			TimeStamp     tsExpiry;


			dwType = SCHANNEL_SHUTDOWN; // Notify schannel that we are about to close the connection.

			OutBuffers[0].pvBuffer = &dwType;
			OutBuffers[0].BufferType = SECBUFFER_TOKEN;
			OutBuffers[0].cbBuffer = sizeof(dwType);

			OutBuffer.cBuffers = 1;
			OutBuffer.pBuffers = OutBuffers;
			OutBuffer.ulVersion = SECBUFFER_VERSION;

			Status = g_pSSPI->ApplyControlToken(phContext, &OutBuffer);
			if (FAILED(Status)) { printf("**** Error 0x%x returned by ApplyControlToken\n", Status); goto cleanup; }


		// Build an SSL close notify message.
			dwSSPIFlags = 
				ISC_REQ_SEQUENCE_DETECT   |
				ISC_REQ_REPLAY_DETECT     |
				ISC_REQ_CONFIDENTIALITY   |
				ISC_RET_EXTENDED_ERROR    |
				ISC_REQ_ALLOCATE_MEMORY   |
				ISC_REQ_STREAM;

			OutBuffers[0].pvBuffer = NULL;
			OutBuffers[0].BufferType = SECBUFFER_TOKEN;
			OutBuffers[0].cbBuffer = 0;

			OutBuffer.cBuffers = 1;
			OutBuffer.pBuffers = OutBuffers;
			OutBuffer.ulVersion = SECBUFFER_VERSION;

			Status = g_pSSPI->InitializeSecurityContextW(phCreds,
														phContext,
														NULL,
														dwSSPIFlags,
														0,
														SECURITY_NATIVE_DREP,
														NULL,
														0,
														phContext,
														&OutBuffer,
														&dwSSPIOutFlags,
														&tsExpiry);

			if (FAILED(Status)) { printf("**** Error 0x%x returned by InitializeSecurityContext\n", Status); goto cleanup; }

			pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
			cbMessage = OutBuffers[0].cbBuffer;


			// Send the close notify message to the server.
			if (pbMessage != NULL && cbMessage != 0) {
				cbData = send(Socket, (const char*)pbMessage, cbMessage, 0);
				if (cbData == SOCKET_ERROR || cbData == 0) {
					Status = WSAGetLastError();
					printf("**** Error %d sending close notify\n", Status);
					DisplayWinSockError(WSAGetLastError());
					goto cleanup;
				}
				printf("Sending Close Notify\n");
				printf("%d bytes of handshake data sent\n", cbData);
				g_pSSPI->FreeContextBuffer(pbMessage); // Free output buffer.
			}


		cleanup:
			g_pSSPI->DeleteSecurityContext(phContext); // Free the security context.
			closesocket(Socket); // Close the socket.

			return Status;
		}

		/*****************************************************************************/
		static void GetNewClientCredentials(CredHandle* phCreds, CtxtHandle* phContext) {

			CredHandle						hCreds;
			SecPkgContext_IssuerListInfoEx	IssuerListInfo;
			PCCERT_CHAIN_CONTEXT			pChainContext;
			CERT_CHAIN_FIND_BY_ISSUER_PARA	FindByIssuerPara;
			PCCERT_CONTEXT					pCertContext;
			TimeStamp						tsExpiry;
			SECURITY_STATUS					Status;


			// Read list of trusted issuers from schannel.
			Status = g_pSSPI->QueryContextAttributesW(phContext, SECPKG_ATTR_ISSUER_LIST_EX, (PVOID)&IssuerListInfo);

			// Enumerate the client certificates.
			ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

			FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
			FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
			FindByIssuerPara.dwKeySpec = 0;
			FindByIssuerPara.cIssuer = IssuerListInfo.cIssuers;
			FindByIssuerPara.rgIssuer = IssuerListInfo.aIssuers;

			pChainContext = NULL;

			while (TRUE) {   // Find a certificate chain.
				pChainContext = CertFindChainInStore(hMyCertStore,
													  X509_ASN_ENCODING,
													  0,
													  CERT_CHAIN_FIND_BY_ISSUER,
													  &FindByIssuerPara,
													  pChainContext);
				if (pChainContext == NULL) { printf("Error 0x%x finding cert chain\n", GetLastError()); break; }

				printf("\ncertificate chain found\n");

		// Get pointer to leaf certificate context.
				pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

				// Create schannel credential.
				SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
				SchannelCred.cCreds = 1;
				SchannelCred.paCred = &pCertContext;

				Status = g_pSSPI->AcquireCredentialsHandleW(
					NULL,                   // Name of principal
					(SEC_WCHAR*)UNISP_NAME_A,           // Name of package
					SECPKG_CRED_OUTBOUND,   // Flags indicating use
					NULL,                   // Pointer to logon ID
					&SchannelCred,          // Package specific data
					NULL,                   // Pointer to GetKey() func
					NULL,                   // Value to pass to GetKey()
					&hCreds,                // (out) Cred Handle
					&tsExpiry);            // (out) Lifetime (optional)
				
				g_pSSPI->FreeCredentialsHandle(phCreds); // Destroy the old credentials.

				*phCreds = hCreds;

			}
		}

		/*****************************************************************************/
		static SECURITY_STATUS ClientHandshakeLoop(SOCKET Socket, PCredHandle phCreds, CtxtHandle* phContext, BOOL fDoInitialRead, SecBuffer* pExtraData) {
			SecBufferDesc   OutBuffer, InBuffer;
			SecBuffer       InBuffers[2], OutBuffers[1];
			DWORD           dwSSPIFlags, dwSSPIOutFlags, cbData, cbIoBuffer;
			TimeStamp       tsExpiry;
			SECURITY_STATUS scRet;
			std::vector<char> IoBuffer(IO_BUFFER_SIZE);
			BOOL            fDoRead;


			dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

			cbIoBuffer = 0;
			fDoRead = fDoInitialRead;

			// Loop until the handshake is finished or an error occurs.
			scRet = SEC_I_CONTINUE_NEEDED;

			while (scRet == SEC_I_CONTINUE_NEEDED || scRet == SEC_E_INCOMPLETE_MESSAGE || scRet == SEC_I_INCOMPLETE_CREDENTIALS) {
				if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE) // Read data from server.
				{
					if (fDoRead) {
						cbData = recv(Socket, &IoBuffer[0] + cbIoBuffer, IO_BUFFER_SIZE - cbIoBuffer, 0);
						if (cbData == SOCKET_ERROR) {
							scRet = SEC_E_INTERNAL_ERROR;
							break;
						} else if (cbData == 0) {
							scRet = SEC_E_INTERNAL_ERROR;
							break;
						}
						cbIoBuffer += cbData;
					} else
						fDoRead = TRUE;
				}

				InBuffers[0].pvBuffer = &IoBuffer[0];
				InBuffers[0].cbBuffer = cbIoBuffer;
				InBuffers[0].BufferType = SECBUFFER_TOKEN;

				InBuffers[1].pvBuffer = NULL;
				InBuffers[1].cbBuffer = 0;
				InBuffers[1].BufferType = SECBUFFER_EMPTY;

				InBuffer.cBuffers = 2;
				InBuffer.pBuffers = InBuffers;
				InBuffer.ulVersion = SECBUFFER_VERSION;

				OutBuffers[0].pvBuffer = NULL;
				OutBuffers[0].BufferType = SECBUFFER_TOKEN;
				OutBuffers[0].cbBuffer = 0;

				OutBuffer.cBuffers = 1;
				OutBuffer.pBuffers = OutBuffers;
				OutBuffer.ulVersion = SECBUFFER_VERSION;


				scRet = g_pSSPI->InitializeSecurityContextW(phCreds, phContext, NULL, dwSSPIFlags, 0, SECURITY_NATIVE_DREP, &InBuffer, 0, NULL, &OutBuffer, &dwSSPIOutFlags, &tsExpiry);

				if (scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED || FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)) {
					if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL) {
						cbData = send(Socket, (char*)(OutBuffers[0].pvBuffer), OutBuffers[0].cbBuffer, 0);
						if (cbData == SOCKET_ERROR || cbData == 0) {
							DisplayWinSockError(WSAGetLastError());
							g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
							g_pSSPI->DeleteSecurityContext(phContext);
							return SEC_E_INTERNAL_ERROR;
						}
						g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
						OutBuffers[0].pvBuffer = NULL;
					}
				}
				if (scRet == SEC_E_INCOMPLETE_MESSAGE) continue;
				
				if (scRet == SEC_E_OK) {
					if (InBuffers[1].BufferType == SECBUFFER_EXTRA) {
						pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED, InBuffers[1].cbBuffer);

						MoveMemory(pExtraData->pvBuffer, &IoBuffer[0] + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer);

						pExtraData->cbBuffer = InBuffers[1].cbBuffer;
						pExtraData->BufferType = SECBUFFER_TOKEN;
					} else {
						pExtraData->pvBuffer = NULL;
						pExtraData->cbBuffer = 0;
						pExtraData->BufferType = SECBUFFER_EMPTY;
					}
					break;
				}

				if (scRet == SEC_I_INCOMPLETE_CREDENTIALS) {
					GetNewClientCredentials(phCreds, phContext);

					// Go around again.
					fDoRead = FALSE;
					scRet = SEC_I_CONTINUE_NEEDED;
					continue;
				}

				// Copy any leftover data from the "extra" buffer, and go around again.
				if (InBuffers[1].BufferType == SECBUFFER_EXTRA) {
					MoveMemory(&IoBuffer[0], &IoBuffer[0] + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer);
					cbIoBuffer = InBuffers[1].cbBuffer;
				} else
					cbIoBuffer = 0;
			}

			// Delete the security context in the case of a fatal error.
			if (FAILED(scRet)) g_pSSPI->DeleteSecurityContext(phContext);
			return scRet;
		}

		/*****************************************************************************/
		static SECURITY_STATUS PerformClientHandshake(SOCKET Socket, PCredHandle phCreds, const std::wstring& ServerName,CtxtHandle* phContext, SecBuffer* pExtraData) {

			SecBufferDesc   OutBuffer;
			SecBuffer       OutBuffers[1];
			DWORD           dwSSPIFlags, dwSSPIOutFlags, cbData;
			TimeStamp       tsExpiry;
			SECURITY_STATUS scRet;


			dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   | ISC_REQ_REPLAY_DETECT     | ISC_REQ_CONFIDENTIALITY   |
				ISC_RET_EXTENDED_ERROR    | ISC_REQ_ALLOCATE_MEMORY   | ISC_REQ_STREAM;


  //  Initiate a ClientHello message and generate a token.
			OutBuffers[0].pvBuffer = NULL;
			OutBuffers[0].BufferType = SECBUFFER_TOKEN;
			OutBuffers[0].cbBuffer = 0;

			OutBuffer.cBuffers = 1;
			OutBuffer.pBuffers = OutBuffers;
			OutBuffer.ulVersion = SECBUFFER_VERSION;

			scRet = g_pSSPI->InitializeSecurityContextW(
				phCreds,
				NULL,
				(SEC_WCHAR*)ServerName.c_str(),
				dwSSPIFlags,
				0,
				SECURITY_NATIVE_DREP,
				NULL,
				0,
				phContext,
				&OutBuffer,
				&dwSSPIOutFlags,
				&tsExpiry);

			// Send response to server if there is one.
			if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL) {
				cbData = send(Socket, (char*)(OutBuffers[0].pvBuffer), OutBuffers[0].cbBuffer, 0);
				if (cbData == SOCKET_ERROR || cbData == 0) {
					g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
					g_pSSPI->DeleteSecurityContext(phContext);
					return SEC_E_INTERNAL_ERROR;
				}
				g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer); // Free output buffer.
				OutBuffers[0].pvBuffer = NULL;
			}

			return ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData);
		}

		/*****************************************************************************/
		static DWORD EncryptSend(SOCKET Socket, CtxtHandle* phContext, char* pbIoBuffer, SecPkgContext_StreamSizes Sizes) {
			SECURITY_STATUS	scRet;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
			SecBufferDesc	Message;        // unsigned long BufferType;  // Type of the buffer (below)
			SecBuffer		Buffers[4];    // void    SEC_FAR * pvBuffer;   // Pointer to the buffer
			DWORD			cbMessage, cbData;
			char*			pbMessage;


			pbMessage = pbIoBuffer + Sizes.cbHeader; // Offset by "header size"
			cbMessage = (DWORD)strlen(pbMessage);


				// Encrypt the HTTP request.
			Buffers[0].pvBuffer = pbIoBuffer;                                // Pointer to buffer 1
			Buffers[0].cbBuffer = Sizes.cbHeader;                        // length of header
			Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;    // Type of the buffer

			Buffers[1].pvBuffer = pbMessage;                                // Pointer to buffer 2
			Buffers[1].cbBuffer = cbMessage;                                // length of the message
			Buffers[1].BufferType = SECBUFFER_DATA;                        // Type of the buffer

			Buffers[2].pvBuffer = pbMessage + cbMessage;        // Pointer to buffer 3
			Buffers[2].cbBuffer = Sizes.cbTrailer;                    // length of the trailor
			Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;    // Type of the buffer

			Buffers[3].pvBuffer = SECBUFFER_EMPTY;                    // Pointer to buffer 4
			Buffers[3].cbBuffer = SECBUFFER_EMPTY;                    // length of buffer 4
			Buffers[3].BufferType = SECBUFFER_EMPTY;                    // Type of the buffer 4


			Message.ulVersion = SECBUFFER_VERSION;    // Version number
			Message.cBuffers = 4;                                    // Number of buffers - must contain four SecBuffer structures.
			Message.pBuffers = Buffers;                        // Pointer to array of buffers
			scRet = g_pSSPI->EncryptMessage(phContext, 0, &Message, 0); // must contain four SecBuffer structures.
		
			return send(Socket, pbIoBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);

		}

		/*****************************************************************************/
		static SECURITY_STATUS ReadDecrypt(SOCKET Socket, PCredHandle phCreds, CtxtHandle* phContext, char* pbIoBuffer, DWORD cbIoBufferLength) {
			SecBuffer		ExtraBuffer;
			SecBuffer*		pDataBuffer, * pExtraBuffer;

			SECURITY_STATUS	scRet;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
			SecBufferDesc	Message;        // unsigned long BufferType;  // Type of the buffer (below)
			SecBuffer		Buffers[4];    // void    SEC_FAR * pvBuffer;   // Pointer to the buffer

			DWORD			cbIoBuffer, cbData, length;
			char*			buff;
			int i;



			  // Read data from server until done.
			cbIoBuffer = 0;
			scRet = 0;
			while (TRUE) // Read some data.
			{
				if (cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE) // get the data
				{
					cbData = recv(Socket, pbIoBuffer + cbIoBuffer, cbIoBufferLength - cbIoBuffer, 0);
					if (cbData == SOCKET_ERROR) {
						scRet = SEC_E_INTERNAL_ERROR;
						break;
					} else if (cbData == 0) // Server disconnected.
					{
						if (cbIoBuffer) {
							scRet = SEC_E_INTERNAL_ERROR;
							return scRet;
						} else
							break; // All Done
					} else // success
					{
						cbIoBuffer += cbData;
					}
				}


				// Decrypt the received data.
				Buffers[0].pvBuffer = pbIoBuffer;
				Buffers[0].cbBuffer = cbIoBuffer;
				Buffers[0].BufferType = SECBUFFER_DATA;  // Initial Type of the buffer 1
				Buffers[1].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 2
				Buffers[2].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 3
				Buffers[3].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 4

				Message.ulVersion = SECBUFFER_VERSION;    // Version number
				Message.cBuffers = 4;                                    // Number of buffers - must contain four SecBuffer structures.
				Message.pBuffers = Buffers;                        // Pointer to array of buffers
				scRet = g_pSSPI->DecryptMessage(phContext, &Message, 0, NULL);
				if (scRet == SEC_I_CONTEXT_EXPIRED) break; // Server signalled end of session
		//      if( scRet == SEC_E_INCOMPLETE_MESSAGE - Input buffer has partial encrypted record, read more
				if (scRet != SEC_E_OK &&
					scRet != SEC_I_RENEGOTIATE &&
					scRet != SEC_I_CONTEXT_EXPIRED) {
					DisplaySECError((DWORD)scRet);
					return scRet;
				}



// Locate data and (optional) extra buffers.
				pDataBuffer = NULL;
				pExtraBuffer = NULL;
				for (i = 1; i < 4; i++) {
					if (pDataBuffer  == NULL && Buffers[i].BufferType == SECBUFFER_DATA) pDataBuffer = &Buffers[i];
					if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA) pExtraBuffer = &Buffers[i];
				}


				// Display the decrypted data.
				if (pDataBuffer) {
					length = pDataBuffer->cbBuffer;
					if (length) // check if last two chars are CR LF
					{
						buff = (char*)pDataBuffer->pvBuffer; // printf( "n-2= %d, n-1= %d \n", buff[length-2], buff[length-1] );
						PrintText(length, (BYTE*)buff);
						if (buff[length-2] == 13 && buff[length-1] == 10) break; // printf("Found CRLF\n");
					}
				}



				// Move any "extra" data to the input buffer.
				if (pExtraBuffer) {
					MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
					cbIoBuffer = pExtraBuffer->cbBuffer; // printf("cbIoBuffer= %d  \n", cbIoBuffer);
				} else
					cbIoBuffer = 0;


						  // The server wants to perform another handshake sequence.
				if (scRet == SEC_I_RENEGOTIATE) {
					printf("Server requested renegotiate!\n");
					scRet = ClientHandshakeLoop(Socket, phCreds, phContext, FALSE, &ExtraBuffer);
					if (scRet != SEC_E_OK) return scRet;

					if (ExtraBuffer.pvBuffer) // Move any "extra" data to the input buffer.
					{
						MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
						cbIoBuffer = ExtraBuffer.cbBuffer;
					}
				}
			} // Loop till CRLF is found at the end of the data

			return SEC_E_OK;
		}

		/*****************************************************************************/
		static SECURITY_STATUS SMTPsession(SOCKET Socket, PCredHandle phCreds, CtxtHandle* phContext) {
			SecPkgContext_StreamSizes	Sizes;            // unsigned long cbBuffer;    // Size of the buffer, in bytes
			SECURITY_STATUS				scRet;            // unsigned long BufferType;  // Type of the buffer (below)
			DWORD						cbIoBufferLength, cbData;


			// Read stream encryption properties.
			scRet = g_pSSPI->QueryContextAttributesW(phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);


			// Create a buffer.
			cbIoBufferLength = Sizes.cbHeader  +  Sizes.cbMaximumMessage  +  Sizes.cbTrailer;
			std::vector<char> pbIoBuffer(cbIoBufferLength);



			// Receive a Response
			scRet = ReadDecrypt(Socket, phCreds, phContext, &pbIoBuffer[0], cbIoBufferLength);
			if (scRet != SEC_E_OK) return scRet;


			// Build the request - must be < maximum message size
			sprintf_s(&pbIoBuffer[0]+Sizes.cbHeader, cbIoBufferLength, "%s", "EHLO \r\n"); // message begins after the header


			// Send a request.
			cbData = EncryptSend(Socket, phContext, &pbIoBuffer[0], Sizes);
			if (cbData == SOCKET_ERROR || cbData == 0) { return SEC_E_INTERNAL_ERROR; }


			// Receive a Response
			scRet = ReadDecrypt(Socket, phCreds, phContext, &pbIoBuffer[0], cbIoBufferLength);
			if (scRet != SEC_E_OK) return scRet;




			// Build the request - must be < maximum message size
			sprintf_s(&pbIoBuffer[0]+Sizes.cbHeader, cbIoBufferLength, "%s", "QUIT \r\n"); // message begins after the header


			// Send a request.
			cbData = EncryptSend(Socket, phContext, &pbIoBuffer[0], Sizes);
			if (cbData == SOCKET_ERROR || cbData == 0) { return SEC_E_INTERNAL_ERROR; }


			// Receive a Response
			scRet = ReadDecrypt(Socket, phCreds, phContext, &pbIoBuffer[0], cbIoBufferLength);
			if (scRet != SEC_E_OK) return scRet;


			return SEC_E_OK;
		}

		/*****************************************************************************/
		void SecureSocket() {
			WSADATA WsaData;
			SOCKET  Socket = INVALID_SOCKET;

			CredHandle hClientCreds;
			CtxtHandle hContext;
			BOOL fCredsInitialized = FALSE;
			BOOL fContextInitialized = FALSE;

			SecBuffer  ExtraData;
			SECURITY_STATUS Status;

			PCCERT_CONTEXT pRemoteCertContext = NULL;

			LoadSecurityLibrary();
			WSAStartup(0x0101, &WsaData);

			CreateCredentials(pszUser, &hClientCreds);

			ConnectToServer("smtp.gmail.com", 465, &Socket);

			PerformClientHandshake(Socket, &hClientCreds, L"smtp.gmail.com", &hContext, &ExtraData);

			fContextInitialized = TRUE;

			Status = g_pSSPI->QueryContextAttributesW(&hContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext);

			DisplayCertChain(pRemoteCertContext, FALSE);

			// Attempt to validate server certificate.
			Status = VerifyServerCertificate(pRemoteCertContext, L"smtp.gmail.com", 0);

			// Free the server certificate context.
			CertFreeCertificateContext(pRemoteCertContext);
			pRemoteCertContext = NULL;

			// Display connection info.
			DisplayConnectionInfo(&hContext);

			// Send Request, recover response. LPSTR pszRequest = "EHLO";
			SMTPsession(Socket, &hClientCreds, &hContext);

			// Send a close_notify alert to the server and close down the connection.
			DisconnectFromServer(Socket, &hClientCreds, &hContext);
			fContextInitialized = FALSE;

			Socket = INVALID_SOCKET;

		cleanup:
			printf("----- Begin Cleanup\n");

				// Free the server certificate context.
			if (pRemoteCertContext) {
				CertFreeCertificateContext(pRemoteCertContext);
				pRemoteCertContext = NULL;
			}

			// Free SSPI context handle.
			if (fContextInitialized) {
				g_pSSPI->DeleteSecurityContext(&hContext);
				fContextInitialized = FALSE;
			}

			// Free SSPI credentials handle.
			if (fCredsInitialized) {
				g_pSSPI->FreeCredentialsHandle(&hClientCreds);
				fCredsInitialized = FALSE;
			}

			// Close socket.
			if (Socket != INVALID_SOCKET) closesocket(Socket);

			// Shutdown WinSock subsystem.
			WSACleanup();

			// Close "MY" certificate store.
			if (hMyCertStore) CertCloseStore(hMyCertStore, 0);

			UnloadSecurityLibrary();


			printf("----- All Done ----- \n");

		}
	}
}