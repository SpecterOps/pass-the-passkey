/**
 * WebAuthn Bridge - TypeScript Implementation
 *
 * Overrides the WebAuthn implementation to act as a proxy between
 * JavaScript in WebView2 and the native .NET WebAuthn implementation.
 */

// ============================================================================
// Type Definitions (must be outside IIFE for TypeScript)
// ============================================================================

/** WebView2 bridge interface exposed by .NET */
interface WebAuthnBridge {
    GetCredentialAsync(optionsJson: string, mediation: string | null): Promise<string | null>;
    CreateCredentialAsync(optionsJson: string): Promise<string | null>;
}

/** Chrome WebView2 host objects interface */
interface ChromeWebView {
    hostObjects: {
        webAuthnBridge?: WebAuthnBridge;
    };
}

declare const chrome: { webview: ChromeWebView };

// Augment PublicKeyCredentialRequestOptions to include hints (WebAuthn Level 3)
interface PublicKeyCredentialRequestOptionsWithHints extends PublicKeyCredentialRequestOptions {
    hints?: string[];
}

interface PublicKeyCredentialCreationOptionsWithHints extends PublicKeyCredentialCreationOptions {
    hints?: string[];
    attestationFormats?: string[];
}

/** Serialized assertion response from C# */
interface SerializedAuthenticatorAssertionResponse {
    clientDataJSON: string; // Base64Url encoded
    authenticatorData: string; // Base64Url encoded
    signature: string; // Base64Url encoded
    userHandle?: string | null | undefined; // Base64Url encoded
}

/** Serialized attestation response from C# */
interface SerializedAuthenticatorAttestationResponse {
    clientDataJSON: string; // Base64Url encoded
    attestationObject: string; // Base64Url encoded
    authenticatorData?: string | null | undefined; // Base64Url encoded
    transports?: string[] | null | undefined;
    publicKey?: string | null | undefined; // Base64Url encoded
    publicKeyAlgorithm?: number | null | undefined;
}

/** Serialized PublicKeyCredential for assertion from C# */
interface SerializedPublicKeyCredentialAssertion {
    id: string;
    rawId?: string | undefined; // Base64Url encoded
    type?: string | undefined;
    authenticatorAttachment?: AuthenticatorAttachment | null | undefined;
    response: SerializedAuthenticatorAssertionResponse;
    clientExtensionResults?: AuthenticationExtensionsClientOutputs | undefined;
}

/** Serialized PublicKeyCredential for attestation from C# */
interface SerializedPublicKeyCredentialAttestation {
    id: string;
    rawId?: string | undefined; // Base64Url encoded
    type?: string | undefined;
    authenticatorAttachment?: AuthenticatorAttachment | null | undefined;
    response: SerializedAuthenticatorAttestationResponse;
    clientExtensionResults?: AuthenticationExtensionsClientOutputs | undefined;
}

// ============================================================================
// IIFE - All implementation details are encapsulated
// ============================================================================

(function (): void {
    // ========================================================================
    // WebAuthn Override - Initialize the bridge
    // ========================================================================

    // Store the original implementation
    const originalGet = navigator.credentials.get.bind(navigator.credentials);
    const originalCreate = navigator.credentials.create.bind(navigator.credentials);

    // Override navigator.credentials.get()
    navigator.credentials.get = async function (
        options?: CredentialRequestOptions
    ): Promise<Credential | null> {
        const bridge = chrome.webview?.hostObjects?.webAuthnBridge;

        // Fall back to original if bridge is unavailable or not a WebAuthn request
        if (!bridge || !options?.publicKey) {
            return originalGet(options);
        }

        try {
            const serializedOptions = serializePublicKeyCredentialRequestOptions(options.publicKey);
            const mediation = options.mediation ?? null;

            const publicKeyCredentialJson = await bridge.GetCredentialAsync(
                JSON.stringify(serializedOptions),
                mediation
            );

            if (publicKeyCredentialJson) {
                const parsedCredential = JSON.parse(publicKeyCredentialJson) as SerializedPublicKeyCredentialAssertion;
                return deserializeAssertionResponse(parsedCredential);
            }

            // Fall back to original if bridge returns null
            return originalGet(options);
        } catch (error) {
            console.error('WebAuthn bridge error:', error);
            throw error;
        }
    };

    // Override navigator.credentials.create()
    navigator.credentials.create = async function (
        options?: CredentialCreationOptions
    ): Promise<Credential | null> {
        const bridge = chrome.webview?.hostObjects?.webAuthnBridge;

        // Fall back to original if bridge is unavailable or not a WebAuthn request
        if (!bridge || !options?.publicKey) {
            return originalCreate(options);
        }

        try {
            const serializedOptions = serializePublicKeyCredentialCreationOptions(options.publicKey);

            const publicKeyCredentialJson = await bridge.CreateCredentialAsync(
                JSON.stringify(serializedOptions)
            );

            if (publicKeyCredentialJson) {
                const parsedCredential = JSON.parse(publicKeyCredentialJson) as SerializedPublicKeyCredentialAttestation;
                return deserializeAttestationResponse(parsedCredential);
            }

            // Fall back to original if bridge returns null
            return originalCreate(options);
        } catch (error) {
            console.error('WebAuthn bridge error:', error);
            throw error;
        }
    };

    // ========================================================================
    // Base64Url Encoding/Decoding Utilities
    // ========================================================================

    /**
     * Converts a BufferSource to a Base64Url encoded string.
     * @param buffer - The ArrayBuffer or ArrayBufferView to convert
     * @returns Base64Url encoded string, or null if buffer is null/undefined
     */
    function arrayBufferToBase64Url(buffer: BufferSource | null | undefined): string | null {
        if (!buffer) {
            return null;
        }

        // Handle ArrayBufferView (e.g., Uint8Array, DataView)
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

    /**
     * Converts a Base64Url encoded string to an ArrayBuffer.
     * @param base64Url - The Base64Url string to convert
     * @returns ArrayBuffer, or null if input is null/undefined
     */
    function base64UrlToArrayBuffer(base64Url: string | null | undefined): ArrayBuffer | null {
        if (!base64Url) {
            return null;
        }

        // Convert Base64Url to Base64
        let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

        // Add padding if needed
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

    // ========================================================================
    // Extension Serialization
    // ========================================================================

    /**
     * Recursively serializes a single extension value, converting ArrayBuffers to Base64Url.
     * @param value - The value to serialize
     * @returns Serialized value with ArrayBuffers converted to Base64Url strings
     */
    function serializeExtensionValue(value: unknown): unknown {
        if (value === null || value === undefined) {
            return value;
        }

        if (value instanceof ArrayBuffer) {
            return arrayBufferToBase64Url(value);
        }

        if (ArrayBuffer.isView(value)) {
            return arrayBufferToBase64Url(value as unknown as BufferSource);
        }

        if (Array.isArray(value)) {
            return value.map(item => serializeExtensionValue(item));
        }

        if (typeof value === 'object') {
            const serialized: Record<string, unknown> = {};
            for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
                serialized[key] = serializeExtensionValue(val);
            }
            return serialized;
        }

        return value;
    }

    /**
     * Serializes WebAuthn extensions, converting all ArrayBuffer values to Base64Url.
     * Handles nested objects like PRF extension inputs.
     * @param extensions - The extensions object to serialize
     * @returns Serialized extensions object, or null if input is null/undefined
     */
    function serializeExtensions(
        extensions: AuthenticationExtensionsClientInputs | undefined
    ): AuthenticationExtensionsClientInputsJSON | null {
        if (!extensions) {
            return null;
        }

        const serialized: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(extensions)) {
            serialized[key] = serializeExtensionValue(value);
        }
        return serialized as AuthenticationExtensionsClientInputsJSON;
    }

    // ========================================================================
    // Request Options Serialization
    // ========================================================================

    /**
     * Serializes PublicKeyCredentialRequestOptions for transport to the C# bridge.
     * Converts all ArrayBuffer values to Base64Url encoded strings.
     * @param publicKey - The PublicKeyCredentialRequestOptions to serialize
     * @returns Serialized options object, or null if input is null/undefined
     */
    function serializePublicKeyCredentialRequestOptions(
        publicKey: PublicKeyCredentialRequestOptions | undefined
    ): (PublicKeyCredentialRequestOptionsJSON & { hints?: string[] }) | null {
        if (!publicKey) {
            return null;
        }

        const serialized: Partial<PublicKeyCredentialRequestOptionsJSON> & { hints?: string[] } = {
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

        const hints = (publicKey as PublicKeyCredentialRequestOptionsWithHints).hints;
        if (hints !== undefined) {
            serialized.hints = hints;
        }

        const extensions = serializeExtensions(publicKey.extensions);
        if (extensions) {
            serialized.extensions = extensions;
        }

        if (publicKey.allowCredentials) {
            serialized.allowCredentials = publicKey.allowCredentials.map(cred => {
                const descriptor: PublicKeyCredentialDescriptorJSON = {
                    type: cred.type,
                    id: arrayBufferToBase64Url(cred.id) ?? '',
                };

                if (cred.transports?.length) {
                    descriptor.transports = [...cred.transports];
                }

                return descriptor;
            });
        }

        return serialized as PublicKeyCredentialRequestOptionsJSON & { hints?: string[] };
    }

    /**
     * Serializes PublicKeyCredentialCreationOptions for transport to the C# bridge.
     * Converts all ArrayBuffer values to Base64Url encoded strings.
     * @param publicKey - The PublicKeyCredentialCreationOptions to serialize
     * @returns Serialized options object, or null if input is null/undefined
     */
    function serializePublicKeyCredentialCreationOptions(
        publicKey: PublicKeyCredentialCreationOptions | undefined
    ): (PublicKeyCredentialCreationOptionsJSON & { hints?: string[]; attestationFormats?: string[] }) | null {
        if (!publicKey) {
            return null;
        }

        const extendedPublicKey = publicKey as PublicKeyCredentialCreationOptionsWithHints;
        const serialized: Partial<PublicKeyCredentialCreationOptionsJSON> & {
            hints?: string[];
            attestationFormats?: string[];
        } = {
            challenge: arrayBufferToBase64Url(extendedPublicKey.challenge) ?? '',
        };

        if (extendedPublicKey.rp) {
            const rp: PublicKeyCredentialRpEntity = {
                name: extendedPublicKey.rp.name,
            };

            if (extendedPublicKey.rp.id !== undefined) {
                rp.id = extendedPublicKey.rp.id;
            }

            serialized.rp = rp;
        }

        if (extendedPublicKey.user) {
            serialized.user = {
                id: arrayBufferToBase64Url(extendedPublicKey.user.id) ?? '',
                name: extendedPublicKey.user.name,
                displayName: extendedPublicKey.user.displayName,
            };
        }

        if (extendedPublicKey.pubKeyCredParams) {
            serialized.pubKeyCredParams = extendedPublicKey.pubKeyCredParams.map(param => ({
                type: param.type,
                alg: param.alg,
            }));
        }

        if (extendedPublicKey.timeout !== undefined) {
            serialized.timeout = extendedPublicKey.timeout;
        }

        if (extendedPublicKey.attestation !== undefined) {
            serialized.attestation = extendedPublicKey.attestation;
        }

        if (extendedPublicKey.attestationFormats !== undefined) {
            serialized.attestationFormats = extendedPublicKey.attestationFormats;
        }

        if (extendedPublicKey.hints !== undefined) {
            serialized.hints = extendedPublicKey.hints;
        }

        if (extendedPublicKey.authenticatorSelection) {
            const authenticatorSelection: AuthenticatorSelectionCriteria = {};

            if (extendedPublicKey.authenticatorSelection.authenticatorAttachment !== undefined) {
                authenticatorSelection.authenticatorAttachment = extendedPublicKey.authenticatorSelection.authenticatorAttachment;
            }

            if (extendedPublicKey.authenticatorSelection.residentKey !== undefined) {
                authenticatorSelection.residentKey = extendedPublicKey.authenticatorSelection.residentKey;
            }

            if (extendedPublicKey.authenticatorSelection.requireResidentKey !== undefined) {
                authenticatorSelection.requireResidentKey = extendedPublicKey.authenticatorSelection.requireResidentKey;
            }

            if (extendedPublicKey.authenticatorSelection.userVerification !== undefined) {
                authenticatorSelection.userVerification = extendedPublicKey.authenticatorSelection.userVerification;
            }

            serialized.authenticatorSelection = authenticatorSelection;
        }

        const creationExtensions = serializeExtensions(extendedPublicKey.extensions);
        if (creationExtensions) {
            serialized.extensions = creationExtensions;
        }

        if (extendedPublicKey.excludeCredentials) {
            serialized.excludeCredentials = extendedPublicKey.excludeCredentials.map(cred => {
                const descriptor: PublicKeyCredentialDescriptorJSON = {
                    type: cred.type,
                    id: arrayBufferToBase64Url(cred.id) ?? '',
                };

                if (cred.transports?.length) {
                    descriptor.transports = [...cred.transports];
                }

                return descriptor;
            });
        }

        return serialized as PublicKeyCredentialCreationOptionsJSON & { hints?: string[]; attestationFormats?: string[] };
    }

    // ========================================================================
    // Response Deserialization
    // ========================================================================

    /**
     * Creates a mock AuthenticatorAssertionResponse object with read-only properties.
     * @param responseData - The serialized response data from C#
     * @returns A mock AuthenticatorAssertionResponse object
     */
    function createAuthenticatorAssertionResponse(
        responseData: SerializedAuthenticatorAssertionResponse
    ): AuthenticatorAssertionResponse {
        const response = Object.create(null) as AuthenticatorAssertionResponse;

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

    /**
     * Creates a mock AuthenticatorAttestationResponse object with read-only properties.
     * @param responseData - The serialized response data from C#
     * @returns A mock AuthenticatorAttestationResponse object
     */
    function createAuthenticatorAttestationResponse(
        responseData: SerializedAuthenticatorAttestationResponse
    ): AuthenticatorAttestationResponse {
        const response = Object.create(null) as AuthenticatorAttestationResponse;

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

        (response as AuthenticatorAttestationResponse & { getTransports(): string[] }).getTransports = function () {
            return responseData.transports ?? [];
        };

        (response as AuthenticatorAttestationResponse & { getPublicKey(): ArrayBuffer | null }).getPublicKey =
            function () {
                return responseData.publicKey ? base64UrlToArrayBuffer(responseData.publicKey) : null;
            };

        (response as AuthenticatorAttestationResponse & { getPublicKeyAlgorithm(): number }).getPublicKeyAlgorithm = function () {
            return responseData.publicKeyAlgorithm ?? 0;
        };

        (response as AuthenticatorAttestationResponse & { getAuthenticatorData(): ArrayBuffer }).getAuthenticatorData = function () {
            return responseData.authenticatorData ? base64UrlToArrayBuffer(responseData.authenticatorData) ?? new ArrayBuffer(0) : new ArrayBuffer(0);
        };

        Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);

        return response;
    }

    /**
     * Deserializes a PublicKeyCredential response from the C# bridge.
     * Creates a mock PublicKeyCredential object with proper read-only properties and methods.
     * @param serializedCredential - The serialized credential from C#
     * @returns A mock PublicKeyCredential object, or null if input is invalid
     */
    function deserializeAssertionResponse(
        serializedCredential: SerializedPublicKeyCredentialAssertion
    ): PublicKeyCredential | null {
        if (!serializedCredential?.response) {
            return null;
        }

        const id = serializedCredential.id;
        const rawId = base64UrlToArrayBuffer(serializedCredential.rawId ?? serializedCredential.id);
        const type = serializedCredential.type ?? 'public-key';
        const authenticatorAttachment = serializedCredential.authenticatorAttachment ?? null;
        const response = createAuthenticatorAssertionResponse(serializedCredential.response);
        const clientExtensionResults = serializedCredential.clientExtensionResults ?? {};

        const credential = Object.create(null) as PublicKeyCredential;

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

        // Instance method: getClientExtensionResults()
        credential.getClientExtensionResults = function (): AuthenticationExtensionsClientOutputs {
            return clientExtensionResults;
        };

        // Instance method: toJSON()
        (credential as PublicKeyCredential & { toJSON(): unknown }).toJSON = function () {
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

    /**
     * Deserializes a PublicKeyCredential attestation response from the C# bridge.
     * Creates a mock PublicKeyCredential object with proper read-only properties and methods.
     * @param serializedCredential - The serialized credential from C#
     * @returns A mock PublicKeyCredential object, or null if input is invalid
     */
    function deserializeAttestationResponse(
        serializedCredential: SerializedPublicKeyCredentialAttestation
    ): PublicKeyCredential | null {
        if (!serializedCredential?.response) {
            return null;
        }

        const id = serializedCredential.id;
        const rawId = base64UrlToArrayBuffer(serializedCredential.rawId ?? serializedCredential.id);
        const type = serializedCredential.type ?? 'public-key';
        const authenticatorAttachment = serializedCredential.authenticatorAttachment ?? null;
        const response = createAuthenticatorAttestationResponse(serializedCredential.response);
        const clientExtensionResults = serializedCredential.clientExtensionResults ?? {};

        const credential = Object.create(null) as PublicKeyCredential;

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

        // Instance method: getClientExtensionResults()
        credential.getClientExtensionResults = function (): AuthenticationExtensionsClientOutputs {
            return clientExtensionResults;
        };

        // Instance method: toJSON()
        (credential as PublicKeyCredential & { toJSON(): unknown }).toJSON = function () {
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
