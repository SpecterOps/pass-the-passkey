"use strict";
(function () {
    const originalGet = navigator.credentials.get.bind(navigator.credentials);
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
            timeout: publicKey.timeout,
            rpId: publicKey.rpId ?? window.location.hostname,
            userVerification: publicKey.userVerification,
            hints: publicKey.hints,
            extensions: serializeExtensions(publicKey.extensions) ?? undefined,
        };
        if (publicKey.allowCredentials) {
            serialized.allowCredentials = publicKey.allowCredentials.map(cred => ({
                type: cred.type,
                id: arrayBufferToBase64Url(cred.id) ?? '',
                transports: cred.transports,
            }));
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
})();
