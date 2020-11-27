package com.boomi.connector.datasecurity;

import java.util.Collection;

import com.boomi.connector.api.ObjectDefinitionRole;
import com.boomi.connector.api.ObjectDefinitions;
import com.boomi.connector.api.ObjectTypes;
import com.boomi.connector.util.BaseBrowser;

/**
 * Not used
 * @author Anthony Rabiaza
 *
 */
public class BoomiDataSecurityBrowser extends BaseBrowser {

    protected BoomiDataSecurityBrowser(BoomiDataSecurityConnection conn) {
        super(conn);
    }

	@Override
	public ObjectDefinitions getObjectDefinitions(String objectTypeId,
			Collection<ObjectDefinitionRole> roles) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ObjectTypes getObjectTypes() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
    public BoomiDataSecurityConnection getConnection() {
        return (BoomiDataSecurityConnection) super.getConnection();
    }
}