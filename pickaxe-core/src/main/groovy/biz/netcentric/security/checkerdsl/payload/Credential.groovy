/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.payload

/**
 * Credential variations for AEM
 * This lists are based on https://github.com/0ang3el/aem-hacker default credentials talk and toolset.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
enum Credential {

    ADMIN("admin","admin"),
    AUTHOR("author","author"),
    GRIOS("grios","password"),
    REPLICATION_RECEIVER("replication-receiver","replication-receiver"),
    VGNADMIN("vgnadmin","vgnadmin"),
    APARKER("aparker@geometrixx.info","aparker"),
    JDOE("jdoe@geometrixx.info","jdoe"),
    JDEVORE("james.devore@spambob.com","password"),
    MMONROE("matt.monroe@mailinator.com","password"),
    MDONALD("aaron.mcdonald@mailinator.com","password"),
    JWERNER("jason.werner@dodgit.com","password");

    private String user
    private String password

    Credential(String user, String password) {
        this.user = user
        this.password = password
    }

    String getUser() {
        return user
    }

    String toBasicAuth(){
        Encoding.toBase64("Basic ${getUser()}:${getPassword()}")
    }

    String getPassword() {
        return password
    }

    static List<Credential> getAll(){
        Arrays.asList(Credential.values())
    }
}