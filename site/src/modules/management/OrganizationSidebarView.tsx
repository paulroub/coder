import type { AuthorizationResponse, Organization } from "api/typesGenerated";
import { Button } from "components/Button/Button";
import {
	Command,
	CommandGroup,
	CommandItem,
	CommandList,
} from "components/Command/Command";
import { Loader } from "components/Loader/Loader";
import {
	Popover,
	PopoverContent,
	PopoverTrigger,
} from "components/Popover/Popover";
import {
	Sidebar as BaseSidebar,
	SettingsSidebarNavItem,
} from "components/Sidebar/Sidebar";
import { UserAvatar } from "components/UserAvatar/UserAvatar";
import type { Permissions } from "contexts/auth/permissions";
import { ChevronDown, Plus } from "lucide-react";
import { useDashboard } from "modules/dashboard/useDashboard";
import { type FC, useState } from "react";
import { Link } from "react-router-dom";

export interface OrganizationWithPermissions extends Organization {
	permissions: AuthorizationResponse;
}

interface SidebarProps {
	/** The active org name, if any.  Overrides activeSettings. */
	activeOrganization: OrganizationWithPermissions | undefined;
	/** Organizations and their permissions or undefined if still fetching. */
	organizations: OrganizationWithPermissions[] | undefined;
	/** Site-wide permissions. */
	permissions: Permissions;
}

/**
 * Organization settings left sidebar menu.
 */
export const OrganizationSidebarView: FC<SidebarProps> = ({
	activeOrganization,
	organizations,
	permissions,
}) => {
	const { showOrganizations } = useDashboard();

	return (
		<BaseSidebar>
			{showOrganizations && (
				<OrganizationsSettingsNavigation
					activeOrganization={activeOrganization}
					organizations={organizations}
					permissions={permissions}
				/>
			)}
		</BaseSidebar>
	);
};

function urlForSubpage(organizationName: string, subpage = ""): string {
	return `/organizations/${organizationName}/${subpage}`;
}

interface OrganizationsSettingsNavigationProps {
	/** The active org name if an org is being viewed. */
	activeOrganization: OrganizationWithPermissions | undefined;
	/** Organizations and their permissions or undefined if still fetching. */
	organizations: OrganizationWithPermissions[] | undefined;
	/** Site-wide permissions. */
	permissions: Permissions;
}

/**
 * Displays navigation items for the active organization and a combobox to
 * switch between organizations.
 *
 * If organizations or their permissions are still loading, show a loader.
 */
const OrganizationsSettingsNavigation: FC<
	OrganizationsSettingsNavigationProps
> = ({ activeOrganization, organizations, permissions }) => {
	// Wait for organizations and their permissions to load
	if (!organizations || !activeOrganization) {
		return <Loader />;
	}

	const [isPopoverOpen, setIsPopoverOpen] = useState(false);

	return (
		<>
			<Popover open={isPopoverOpen} onOpenChange={setIsPopoverOpen}>
				<PopoverTrigger asChild>
					<Button
						variant="outline"
						aria-expanded={isPopoverOpen}
						className="w-60 justify-between p-2 h-11"
					>
						<div className="flex flex-row gap-2 items-center p-2">
							{activeOrganization && (
								<UserAvatar
									key={activeOrganization.id}
									size="sm"
									username={activeOrganization.display_name}
									avatarURL={activeOrganization.icon}
								/>
							)}
							{activeOrganization?.display_name || activeOrganization?.name}
						</div>
						<ChevronDown />
					</Button>
				</PopoverTrigger>
				<PopoverContent align="start" className="w-60">
					<Command>
						<CommandList>
							<CommandGroup className="pb-2">
								{organizations.map((organization) => (
									<Link
										key={organization.id}
										to={urlForSubpage(organization.name)}
										className="no-underline visited:text-content-secondary"
									>
										<CommandItem
											value={organization.name}
											onSelect={() => {
												setIsPopoverOpen(false);
											}}
										>
											<UserAvatar
												key={organization.id}
												size="sm"
												username={organization.display_name}
												avatarURL={organization.icon}
											/>
											{organization.display_name || organization.name}
										</CommandItem>
									</Link>
								))}
								{permissions.createOrganization && (
									<>
										<hr className="h-px my-2 border-none bg-border -mx-2" />
										<Button variant="subtle" className="w-full h-8">
											<a
												href="/organizations/new"
												className="flex items-center gap-1 no-underline hover:text-content-primary visited:text-content-secondary"
											>
												<Plus /> Create Organization
											</a>
										</Button>
									</>
								)}
							</CommandGroup>
						</CommandList>
					</Command>
				</PopoverContent>
			</Popover>
			<OrganizationSettingsNavigation
				key={activeOrganization.id}
				organization={activeOrganization}
			/>
		</>
	);
};

interface OrganizationSettingsNavigationProps {
	organization: OrganizationWithPermissions;
}

const OrganizationSettingsNavigation: FC<
	OrganizationSettingsNavigationProps
> = ({ organization }) => {
	return (
		<>
			<div className="flex flex-col gap-1 my-2">
				{organization.permissions.editMembers && (
					<SettingsSidebarNavItem end href={urlForSubpage(organization.name)}>
						Members
					</SettingsSidebarNavItem>
				)}
				{organization.permissions.editGroups && (
					<SettingsSidebarNavItem
						href={urlForSubpage(organization.name, "groups")}
					>
						Groups
					</SettingsSidebarNavItem>
				)}
				{organization.permissions.assignOrgRole && (
					<SettingsSidebarNavItem
						href={urlForSubpage(organization.name, "roles")}
					>
						Roles
					</SettingsSidebarNavItem>
				)}
				{organization.permissions.viewProvisioners && (
					<SettingsSidebarNavItem
						href={urlForSubpage(organization.name, "provisioners")}
					>
						Provisioners
					</SettingsSidebarNavItem>
				)}
				{organization.permissions.viewIdpSyncSettings && (
					<SettingsSidebarNavItem
						href={urlForSubpage(organization.name, "idp-sync")}
					>
						IdP Sync
					</SettingsSidebarNavItem>
				)}
				{organization.permissions.editOrganization && (
					<SettingsSidebarNavItem
						href={urlForSubpage(organization.name, "settings")}
					>
						Settings
					</SettingsSidebarNavItem>
				)}
			</div>
		</>
	);
};
