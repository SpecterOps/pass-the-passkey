"use strict";
(function () {
    const originalGet = navigator.credentials.get.bind(navigator.credentials);
    const originalCreate = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.get = async function (options) {
        const bridge = chrome.webview?.hostObjects?.webAuthnBridge;
        if (!bridge || !options?.publicKey) {
            return originalGet(options);
        }
        try {
            const serializedOptions = serializePublicKeyCredentialRequestOptions(options.publicKey);
            const mediation = options.mediation ?? null;
            const publicKeyCredentialJson = await bridge.GetCredentialAsync(JSON.stringify(serializedOptions), mediation);
            if (publicKeyCredentialJson) {
                const parsedCredential = JSON.parse(publicKeyCredentialJson);
                return deserializeAssertionResponse(parsedCredential);
            }
            return originalGet(options);
        }
        catch (error) {
            console.error('WebAuthn bridge error:', error);
            throw error;
        }
    };
    navigator.credentials.create = async function (options) {
        const bridge = chrome.webview?.hostObjects?.webAuthnBridge;
        if (!bridge || !options?.publicKey) {
            return originalCreate(options);
        }
        try {
            const serializedOptions = serializePublicKeyCredentialCreationOptions(options.publicKey);
            const publicKeyCredentialJson = await bridge.CreateCredentialAsync(JSON.stringify(serializedOptions), options.mediation ?? null);
            if (publicKeyCredentialJson) {
                const parsedCredential = JSON.parse(publicKeyCredentialJson);
                return deserializeAttestationResponse(parsedCredential);
            }
            return originalCreate(options);
        }
        catch (error) {
            console.error('WebAuthn bridge error:', error);
            throw error;
        }
    };
    function arrayBufferToBase64Url(buffer) {
        if (!buffer) {
            return null;
        }
        const arrayBuffer = ArrayBuffer.isView(buffer) ? buffer.buffer : buffer;
        const bytes = new Uint8Array(arrayBuffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    function base64UrlToArrayBuffer(base64Url) {
        if (!base64Url) {
            return null;
        }
        let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = base64.length % 4;
        if (padding) {
            base64 += '='.repeat(4 - padding);
        }
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
    function serializeExtensionValue(value) {
        if (value === null || value === undefined) {
            return value;
        }
        if (value instanceof ArrayBuffer) {
            return arrayBufferToBase64Url(value);
        }
        if (ArrayBuffer.isView(value)) {
            return arrayBufferToBase64Url(value);
        }
        if (Array.isArray(value)) {
            return value.map(item => serializeExtensionValue(item));
        }
        if (typeof value === 'object') {
            const serialized = {};
            for (const [key, val] of Object.entries(value)) {
                serialized[key] = serializeExtensionValue(val);
            }
            return serialized;
        }
        return value;
    }
    function serializeExtensions(extensions) {
        if (!extensions) {
            return null;
        }
        const serialized = {};
        for (const [key, value] of Object.entries(extensions)) {
            serialized[key] = serializeExtensionValue(value);
        }
        return serialized;
    }
    function serializePublicKeyCredentialRequestOptions(publicKey) {
        if (!publicKey) {
            return null;
        }
        const serialized = {
            challenge: arrayBufferToBase64Url(publicKey.challenge) ?? '',
        };
        if (publicKey.timeout !== undefined) {
            serialized.timeout = publicKey.timeout;
        }
        if (publicKey.rpId !== undefined) {
            serialized.rpId = publicKey.rpId;
        }
        if (publicKey.userVerification !== undefined) {
            serialized.userVerification = publicKey.userVerification;
        }
        const hints = publicKey.hints;
        if (hints !== undefined) {
            serialized.hints = hints;
        }
        const extensions = serializeExtensions(publicKey.extensions);
        if (extensions) {
            serialized.extensions = extensions;
        }
        if (publicKey.allowCredentials) {
            serialized.allowCredentials = publicKey.allowCredentials.map(cred => {
                const descriptor = {
                    type: cred.type,
                    id: arrayBufferToBase64Url(cred.id) ?? '',
                };
                if (cred.transports?.length) {
                    descriptor.transports = [...cred.transports];
                }
                return descriptor;
            });
        }
        return serialized;
    }
    function serializePublicKeyCredentialCreationOptions(publicKey) {
        if (!publicKey) {
            return null;
        }
        const serialized = {
            challenge: arrayBufferToBase64Url(publicKey.challenge) ?? '',
        };
        if (publicKey.rp) {
            const rp = {
                name: publicKey.rp.name,
            };
            if (publicKey.rp.id !== undefined) {
                rp.id = publicKey.rp.id;
            }
            serialized.rp = rp;
        }
        if (publicKey.user) {
            serialized.user = {
                id: arrayBufferToBase64Url(publicKey.user.id) ?? '',
                name: publicKey.user.name,
                displayName: publicKey.user.displayName,
            };
        }
        if (publicKey.pubKeyCredParams) {
            serialized.pubKeyCredParams = publicKey.pubKeyCredParams.map(param => ({
                type: param.type,
                alg: param.alg,
            }));
        }
        if (publicKey.timeout !== undefined) {
            serialized.timeout = publicKey.timeout;
        }
        if (publicKey.attestation !== undefined) {
            serialized.attestation = publicKey.attestation;
        }
        if (publicKey.attestationFormats !== undefined) {
            serialized.attestationFormats = publicKey.attestationFormats;
        }
        if (publicKey.hints !== undefined) {
            serialized.hints = publicKey.hints;
        }
        if (publicKey.authenticatorSelection) {
            const authenticatorSelection = {};
            if (publicKey.authenticatorSelection.authenticatorAttachment !== undefined) {
                authenticatorSelection.authenticatorAttachment = publicKey.authenticatorSelection.authenticatorAttachment;
            }
            if (publicKey.authenticatorSelection.residentKey !== undefined) {
                authenticatorSelection.residentKey = publicKey.authenticatorSelection.residentKey;
            }
            if (publicKey.authenticatorSelection.requireResidentKey !== undefined) {
                authenticatorSelection.requireResidentKey = publicKey.authenticatorSelection.requireResidentKey;
            }
            if (publicKey.authenticatorSelection.userVerification !== undefined) {
                authenticatorSelection.userVerification = publicKey.authenticatorSelection.userVerification;
            }
            serialized.authenticatorSelection = authenticatorSelection;
        }
        const creationExtensions = serializeExtensions(publicKey.extensions);
        if (creationExtensions) {
            serialized.extensions = creationExtensions;
        }
        if (publicKey.excludeCredentials) {
            serialized.excludeCredentials = publicKey.excludeCredentials.map(cred => {
                const descriptor = {
                    type: cred.type,
                    id: arrayBufferToBase64Url(cred.id) ?? '',
                };
                if (cred.transports?.length) {
                    descriptor.transports = [...cred.transports];
                }
                return descriptor;
            });
        }
        return serialized;
    }
    function createAuthenticatorAssertionResponse(responseData) {
        const response = Object.create(null);
        Object.defineProperties(response, {
            clientDataJSON: {
                value: base64UrlToArrayBuffer(responseData.clientDataJSON),
                writable: false,
                enumerable: true,
                configurable: false,
            },
            authenticatorData: {
                value: base64UrlToArrayBuffer(responseData.authenticatorData),
                writable: false,
                enumerable: true,
                configurable: false,
            },
            signature: {
                value: base64UrlToArrayBuffer(responseData.signature),
                writable: false,
                enumerable: true,
                configurable: false,
            },
            userHandle: {
                value: responseData.userHandle ? base64UrlToArrayBuffer(responseData.userHandle) : null,
                writable: false,
                enumerable: true,
                configurable: false,
            },
        });
        Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
        return response;
    }
    function createAuthenticatorAttestationResponse(responseData) {
        const response = Object.create(null);
        Object.defineProperties(response, {
            clientDataJSON: {
                value: base64UrlToArrayBuffer(responseData.clientDataJSON),
                writable: false,
                enumerable: true,
                configurable: false,
            },
            attestationObject: {
                value: base64UrlToArrayBuffer(responseData.attestationObject),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        });
        response.getTransports = function () {
            return responseData.transports ?? [];
        };
        response.getPublicKey =
            function () {
                return responseData.publicKey ? base64UrlToArrayBuffer(responseData.publicKey) : null;
            };
        response.getPublicKeyAlgorithm = function () {
            return responseData.publicKeyAlgorithm ?? 0;
        };
        response.getAuthenticatorData = function () {
            return responseData.authenticatorData ? base64UrlToArrayBuffer(responseData.authenticatorData) ?? new ArrayBuffer(0) : new ArrayBuffer(0);
        };
        Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
        return response;
    }
    function deserializeAssertionResponse(serializedCredential) {
        if (!serializedCredential?.response) {
            return null;
        }
        const id = serializedCredential.id;
        const rawId = base64UrlToArrayBuffer(serializedCredential.rawId ?? serializedCredential.id);
        const type = serializedCredential.type ?? 'public-key';
        const authenticatorAttachment = serializedCredential.authenticatorAttachment ?? null;
        const response = createAuthenticatorAssertionResponse(serializedCredential.response);
        const clientExtensionResults = serializedCredential.clientExtensionResults ?? {};
        const credential = Object.create(null);
        Object.defineProperties(credential, {
            id: {
                value: id,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            rawId: {
                value: rawId,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            type: {
                value: type,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            authenticatorAttachment: {
                value: authenticatorAttachment,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            response: {
                value: response,
                writable: false,
                enumerable: true,
                configurable: false,
            },
        });
        credential.getClientExtensionResults = function () {
            return clientExtensionResults;
        };
        credential.toJSON = function () {
            return {
                id,
                rawId: serializedCredential.rawId ?? serializedCredential.id,
                type,
                authenticatorAttachment,
                clientExtensionResults,
                response: {
                    clientDataJSON: serializedCredential.response.clientDataJSON,
                    authenticatorData: serializedCredential.response.authenticatorData,
                    signature: serializedCredential.response.signature,
                    userHandle: serializedCredential.response.userHandle ?? null,
                },
            };
        };
        Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
        return credential;
    }
    function deserializeAttestationResponse(serializedCredential) {
        if (!serializedCredential?.response) {
            return null;
        }
        const id = serializedCredential.id;
        const rawId = base64UrlToArrayBuffer(serializedCredential.rawId ?? serializedCredential.id);
        const type = serializedCredential.type ?? 'public-key';
        const authenticatorAttachment = serializedCredential.authenticatorAttachment ?? null;
        const response = createAuthenticatorAttestationResponse(serializedCredential.response);
        const clientExtensionResults = serializedCredential.clientExtensionResults ?? {};
        const credential = Object.create(null);
        Object.defineProperties(credential, {
            id: {
                value: id,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            rawId: {
                value: rawId,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            type: {
                value: type,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            authenticatorAttachment: {
                value: authenticatorAttachment,
                writable: false,
                enumerable: true,
                configurable: false,
            },
            response: {
                value: response,
                writable: false,
                enumerable: true,
                configurable: false,
            },
        });
        credential.getClientExtensionResults = function () {
            return clientExtensionResults;
        };
        credential.toJSON = function () {
            return {
                id,
                rawId: serializedCredential.rawId ?? serializedCredential.id,
                type,
                authenticatorAttachment,
                clientExtensionResults,
                response: {
                    clientDataJSON: serializedCredential.response.clientDataJSON,
                    attestationObject: serializedCredential.response.attestationObject,
                    authenticatorData: serializedCredential.response.authenticatorData ?? null,
                    transports: serializedCredential.response.transports ?? null,
                    publicKey: serializedCredential.response.publicKey ?? null,
                    publicKeyAlgorithm: serializedCredential.response.publicKeyAlgorithm ?? null,
                },
            };
        };
        Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
        return credential;
    }
})();
