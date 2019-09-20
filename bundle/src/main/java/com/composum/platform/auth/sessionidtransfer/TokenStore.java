package com.composum.platform.auth.sessionidtransfer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** A service to store arbitrary pojos for some time, generating secure random tokens to retrieve them later. */
public interface TokenStore {

    /**
     * Saves some information in the token store, returning a secure random token that can be used to access this later.
     *
     * @param <T>       the type of {info}
     * @param info      the information to store at the token
     * @param timeoutms timeout in milliseconds after which the information will be deleted.
     * @return an alpanumeric token to access the information later
     */
    @Nonnull
    <T> String save(@Nonnull T info, long timeoutms);

    /**
     * Retrieves the information stored at the token once. The stored information is deleted and cannot be retrieved
     * again.
     *
     * @param <T>   the type of the stored information
     * @param token the token
     * @param clazz the type of the stored information
     * @return the stored information if it hasn't timed out yet and if it conforms to {clazz}, otherwise null
     */
    @Nullable
    <T> T retrieveAndDelete(@Nonnull String token, Class<T> clazz);

}
