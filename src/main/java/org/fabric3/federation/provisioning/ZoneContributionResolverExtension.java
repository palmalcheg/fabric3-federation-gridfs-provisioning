/*
 * Fabric3
 * Copyright (c) 2009-2011 Metaform Systems
 *
 * Fabric3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version, with the
 * following exception:
 *
 * Linking this software statically or dynamically with other
 * modules is making a combined work based on this software.
 * Thus, the terms and conditions of the GNU General Public
 * License cover the whole combination.
 *
 * As a special exception, the copyright holders of this software
 * give you permission to link this software with independent
 * modules to produce an executable, regardless of the license
 * terms of these independent modules, and to copy and distribute
 * the resulting executable under terms of your choice, provided
 * that you also meet, for each linked independent module, the
 * terms and conditions of the license of that module. An
 * independent module is a module which is not derived from or
 * based on this software. If you modify this software, you may
 * extend this exception to your version of the software, but
 * you are not obligated to do so. If you do not wish to do so,
 * delete this exception statement from your version.
 *
 * Fabric3 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the
 * GNU General Public License along with Fabric3.
 * If not, see <http://www.gnu.org/licenses/>.
 */
package org.fabric3.federation.provisioning;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

import org.fabric3.api.SecuritySubject;
import org.fabric3.api.annotation.monitor.Monitor;
import org.fabric3.spi.contribution.Contribution;
import org.fabric3.spi.contribution.ContributionResolverExtension;
import org.fabric3.spi.contribution.ContributionServiceListener;
import org.fabric3.spi.contribution.ResolutionException;
import org.fabric3.spi.security.AuthenticationException;
import org.fabric3.spi.security.AuthenticationService;
import org.fabric3.spi.security.AuthorizationException;
import org.fabric3.spi.security.AuthorizationService;
import org.fabric3.spi.security.UsernamePasswordToken;
import org.jgroups.blocks.GridFile;
import org.jgroups.blocks.GridFilesystem;
import org.jgroups.blocks.ReplCache;
import org.oasisopen.sca.annotation.EagerInit;
import org.oasisopen.sca.annotation.Init;
import org.oasisopen.sca.annotation.Property;
import org.oasisopen.sca.annotation.Reference;

/**
 * Resolves contributions in a domain. Resolution is done by querying Grid Filesystem
 * 
 * @author palmalcheg
 */
@EagerInit
public class ZoneContributionResolverExtension implements
		ContributionResolverExtension, ContributionServiceListener {

	private ProvisionMonitor monitor;
	private boolean secure;
	private String username;
	private String password;

	protected String role = "provision.client";

	private String props = "udp.xml";
	private String cluster_name = "gridfs_cluster";
	private String metadata_cluster_name = "metadata_gridfs_cluster";
	private short default_repl_count = 1;
	private int default_chunk_size = 4000;

	private AuthenticationService authenticationService;
	private AuthorizationService authorizationService;
	private GridFilesystem fs;

	public ZoneContributionResolverExtension(@Monitor ProvisionMonitor monitor,
			@Reference AuthenticationService authenticationService,
			@Reference AuthorizationService authorizationService) {
		this.monitor = monitor;
		this.authenticationService = authenticationService;
		this.authorizationService = authorizationService;
	}

	@Property(required = false)
	public void setSecure(boolean secure) {
		this.secure = secure;
	}

	@Property(required = false)
	public void setUsername(String username) {
		this.username = username;
	}

	@Property(required = false)
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * Role required by subjects authenticating to provision a contribution.
	 * 
	 * @param role
	 *            role required by subjects authenticating to provision a
	 *            contribution
	 */
	@Property(required = false)
	public void setRole(String role) {
		this.role = role;
	}

	@Property(required = false)
	public void setReplicationCount(short replCount) {
		this.default_repl_count = replCount;
	}

	@Property(required = false)
	public void setGridConfigration(String props) {
		this.props = props;
	}

	@Property(required = false)
	public void setGridClusterName(String cluster_name) {
		this.cluster_name = cluster_name;
	}

	@Property(required = false)
	public void setGridMetaDataClusterName(String metadata_cluster_name) {
		this.metadata_cluster_name = metadata_cluster_name;
	}

	@Init
	public void init() throws Exception {
		if (secure) {
			if (username == null) {
				monitor.warnUsername();
			}
			if (password == null) {
				monitor.warnPassword();
			}
		}
		ReplCache<String, byte[]> data = new ReplCache<String, byte[]>(props,
				cluster_name);
		ReplCache<String, GridFile.Metadata> metadata = new ReplCache<String, GridFile.Metadata>(
				props, metadata_cluster_name);
		data.start();
		metadata.start();
		fs = new GridFilesystem(data, metadata, default_repl_count,
				default_chunk_size);
	}

	public InputStream resolve(URI contributionUri) throws ResolutionException {
		if (secure && !checkAccess()) {
			throw new ResolutionException("Grid FS Provision denined : "
					+ contributionUri.toString());
		}
		try {
			if ( contributionUri== null){
				throw new ResolutionException("Null  contributionUri " );
			} 
			monitor.resolving(contributionUri);
			return fs.getInput(contributionUri.toString());
		} catch (IOException e) {
			monitor.error("Can't resolve Contribution from URL :" + contributionUri.toString(), e);
			throw new ResolutionException(e);
		}
	}

	protected boolean checkAccess() {
		try {
			UsernamePasswordToken token = new UsernamePasswordToken(username,
					password);
			SecuritySubject subject = authenticationService.authenticate(token);
			authorizationService.checkRole(subject, role);
			return true;
		} catch (AuthenticationException e) {
			monitor.badAuthentication(e);
			return false;
		} catch (AuthorizationException e) {
			monitor.badAuthorization(e);
			return false;
		}
	}

	private static void fastChannelCopy(final ReadableByteChannel src,
			final WritableByteChannel dest) throws IOException {
		final ByteBuffer buffer = ByteBuffer.allocateDirect(16 * 1024);
		while (src.read(buffer) != -1) {
			buffer.flip();
			dest.write(buffer);
			buffer.compact();
		}
		buffer.flip();
		while (buffer.hasRemaining()) {
			dest.write(buffer);
		}
	}

	public void onInstall(Contribution contribution) {
		onStore(contribution);
	}

	public void onProcessManifest(Contribution arg0) {
	}

	public void onRemove(Contribution contribution) {
		File out_file = fs.getFile(contribution.getUri().toString());
		if (out_file.exists() && out_file.isFile()) {
			if (out_file instanceof GridFile)
				((GridFile) out_file).delete(true);
			else
				out_file.delete();
		}
	}

	public void onStore(Contribution contribution) {
		
		File out_file = fs.getFile(contribution.getUri().toString());
		
		if (out_file.exists() && out_file.isFile()) {
			return;
		}
		
		URL url = contribution.getLocation();
		try {
			ReadableByteChannel src = Channels.newChannel(url.openStream());
			WritableByteChannel dest = Channels.newChannel(fs.getOutput(contribution.getUri().toString()));

			fastChannelCopy(src, dest);

			src.close();
			dest.close();
		} catch (IOException e) {
			monitor.error("Cannot store contribuion in Grid : ", e);
			throw new RuntimeException(e);
		}
	}

	public void onUninstall(Contribution contribution) {
		onRemove(contribution);
	}

	public void onUpdate(Contribution contribution) {
		onRemove(contribution);
		onStore(contribution);
	}

}