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

/** Serialized credential descriptor for transport to C# */
interface SerializedPublicKeyCredentialDescriptor {
    type: string;
    id: string; // Base64Url encoded
    transports?: string[] | undefined;
}

/** Serialized request options for transport to C# */
interface SerializedPublicKeyCredentialRequestOptions {
    challenge: string; // Base64Url encoded
    timeout?: number | undefined;
    rpId?: string | undefined;
    userVerification?: UserVerificationRequirement | undefined;
    hints?: string[] | undefined;
    allowCredentials?: SerializedPublicKeyCredentialDescriptor[] | undefined;
    extensions?: Record<string, unknown> | undefined;
}

/** Serialized assertion response from C# */
interface SerializedAuthenticatorAssertionResponse {
    clientDataJSON: string; // Base64Url encoded
    authenticatorData: string; // Base64Url encoded
    signature: string; // Base64Url encoded
    userHandle?: string | null | undefined; // Base64Url encoded
}

/** Serialized PublicKeyCredential from C# */
interface SerializedPublicKeyCredential {
    id: string;
    rawId?: string | undefined; // Base64Url encoded
    type?: string | undefined;
    authenticatorAttachment?: AuthenticatorAttachment | null | undefined;
    response: SerializedAuthenticatorAssertionResponse;
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

    // Override navigator.credentials.get()
    navigator.credentials.get = async function (
        options?: CredentialRequestOptions
    ): Promise<Credential | null> {
        const bridge = chrome.webview?.hostObjects?.webAuthnBridge;

        // Fall back to original if bridge unavailable or not a WebAuthn request
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
                const parsedCredential = JSON.parse(publicKeyCredentialJson) as SerializedPublicKeyCredential;
                return deserializeAssertionResponse(parsedCredential);
            }

            // Fall back to original if bridge returns null
            return originalGet(options);
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
    ): Record<string, unknown> | null {
        if (!extensions) {
            return null;
        }

        const serialized: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(extensions)) {
            serialized[key] = serializeExtensionValue(value);
        }
        return serialized;
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
    ): SerializedPublicKeyCredentialRequestOptions | null {
        if (!publicKey) {
            return null;
        }

        const serialized: SerializedPublicKeyCredentialRequestOptions = {
            challenge: arrayBufferToBase64Url(publicKey.challenge) ?? '',
            timeout: publicKey.timeout,
            rpId: publicKey.rpId,
            userVerification: publicKey.userVerification,
            hints: (publicKey as PublicKeyCredentialRequestOptionsWithHints).hints,
            extensions: serializeExtensions(publicKey.extensions) ?? undefined,
        };

        if (publicKey.allowCredentials) {
            serialized.allowCredentials = publicKey.allowCredentials.map(cred => ({
                type: cred.type,
                id: arrayBufferToBase64Url(cred.id) ?? '',
                transports: cred.transports as string[] | undefined,
            }));
        }

        return serialized;
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
     * Deserializes a PublicKeyCredential response from the C# bridge.
     * Creates a mock PublicKeyCredential object with proper read-only properties and methods.
     * @param serializedCredential - The serialized credential from C#
     * @returns A mock PublicKeyCredential object, or null if input is invalid
     */
    function deserializeAssertionResponse(
        serializedCredential: SerializedPublicKeyCredential
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
})();