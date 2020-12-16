package com.boomi.connector.datasecurity;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import com.boomi.connector.api.BrowseContext;
import com.boomi.connector.api.Browser;
import com.boomi.connector.api.Operation;
import com.boomi.connector.api.OperationContext;
import com.boomi.connector.util.BaseConnector;

/**
 * BoomiDataProcessorConnector class with utilities
 * @author Anthony Rabiaza
 *
 */
public class BoomiDataSecurityConnector extends BaseConnector {

    @Override
    public Browser createBrowser(BrowseContext context) {
        return new BoomiDataSecurityBrowser(createConnection(context));
    }    

    @Override
    protected Operation createExecuteOperation(OperationContext context) {
        return new BoomiDataSecurityExecuteOperation(createConnection(context));
    }

    @Override
    protected Operation createGetOperation(OperationContext context) {
        return new BoomiDataSecurityGetOperation(createConnection(context));
    }
   
    private BoomiDataSecurityConnection createConnection(BrowseContext context) {
        return new BoomiDataSecurityConnection(context);
    }
    
	/**
	 * Utility to convert InputStream to String
	 * @param is
	 * @return
	 * @throws IOException
	 */
	public static String inputStreamToString(InputStream is) throws IOException {
		try (BufferedReader buffer = new BufferedReader(new InputStreamReader(is))) {
			return buffer.lines().collect(Collectors.joining("\n"));
		}
	}
}