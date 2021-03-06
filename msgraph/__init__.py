
# # -*- coding: utf-8 -*- 
# """
# # Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
# """

# from .model.body_type import BodyType
# from .model.importance import Importance
# from .model.calendar_color import CalendarColor
# from .model.response_type import ResponseType
# from .model.sensitivity import Sensitivity
# from .model.recurrence_pattern_type import RecurrencePatternType
# from .model.day_of_week import DayOfWeek
# from .model.week_index import WeekIndex
# from .model.recurrence_range_type import RecurrenceRangeType
# from .model.free_busy_status import FreeBusyStatus
# from .model.event_type import EventType
# from .model.attendee_type import AttendeeType
# from .model.meeting_message_type import MeetingMessageType
# from .model.alternative_security_id import AlternativeSecurityId
# from .model.license_units_detail import LicenseUnitsDetail
# from .model.service_plan_info import ServicePlanInfo
# from .model.assigned_plan import AssignedPlan
# from .model.provisioned_plan import ProvisionedPlan
# from .model.verified_domain import VerifiedDomain
# from .model.assigned_license import AssignedLicense
# from .model.password_profile import PasswordProfile
# from .model.reminder import Reminder
# from .model.date_time_time_zone import DateTimeTimeZone
# from .model.location import Location
# from .model.physical_address import PhysicalAddress
# from .model.item_body import ItemBody
# from .model.recipient import Recipient
# from .model.email_address import EmailAddress
# from .model.response_status import ResponseStatus
# from .model.patterned_recurrence import PatternedRecurrence
# from .model.recurrence_pattern import RecurrencePattern
# from .model.recurrence_range import RecurrenceRange
# from .model.attendee import Attendee
# from .model.identity_set import IdentitySet
# from .model.identity import Identity
# from .model.quota import Quota
# from .model.item_reference import ItemReference
# from .model.audio import Audio
# from .model.deleted import Deleted
# from .model.file import File
# from .model.hashes import Hashes
# from .model.file_system_info import FileSystemInfo
# from .model.folder import Folder
# from .model.image import Image
# from .model.geo_coordinates import GeoCoordinates
# from .model.photo import Photo
# from .model.remote_item import RemoteItem
# from .model.search_result import SearchResult
# from .model.shared import Shared
# from .model.special_folder import SpecialFolder
# from .model.video import Video
# from .model.package import Package
# from .model.sharing_invitation import SharingInvitation
# from .model.sharing_link import SharingLink
# from .model.thumbnail import Thumbnail
# from .model.entity import Entity
# from .model.directory_object import DirectoryObject
# from .model.device import Device
# from .model.directory_role import DirectoryRole
# from .model.directory_role_template import DirectoryRoleTemplate
# from .model.group import Group
# from .model.conversation_thread import ConversationThread
# from .model.calendar import Calendar
# from .model.outlook_item import OutlookItem
# from .model.event import Event
# from .model.conversation import Conversation
# from .model.profile_photo import ProfilePhoto
# from .model.drive import Drive
# from .model.subscribed_sku import SubscribedSku
# from .model.organization import Organization
# from .model.user import User
# from .model.message import Message
# from .model.mail_folder import MailFolder
# from .model.calendar_group import CalendarGroup
# from .model.contact import Contact
# from .model.contact_folder import ContactFolder
# from .model.attachment import Attachment
# from .model.file_attachment import FileAttachment
# from .model.item_attachment import ItemAttachment
# from .model.event_message import EventMessage
# from .model.reference_attachment import ReferenceAttachment
# from .model.post import Post
# from .model.drive_item import DriveItem
# from .model.permission import Permission
# from .model.thumbnail_set import ThumbnailSet
# from .model.subscription import Subscription
# from .request.entity_request import EntityRequest
# from .request.entity_request_builder import EntityRequestBuilder
# from .request.directory_object_request import DirectoryObjectRequest
# from .request.directory_object_request_builder import DirectoryObjectRequestBuilder
# from .request.device_request import DeviceRequest
# from .request.device_request_builder import DeviceRequestBuilder
# from .request.directory_role_request import DirectoryRoleRequest
# from .request.directory_role_request_builder import DirectoryRoleRequestBuilder
# from .request.directory_role_template_request import DirectoryRoleTemplateRequest
# from .request.directory_role_template_request_builder import DirectoryRoleTemplateRequestBuilder
# from .request.group_request import GroupRequest
# from .request.group_request_builder import GroupRequestBuilder
# from .request.conversation_thread_request import ConversationThreadRequest
# from .request.conversation_thread_request_builder import ConversationThreadRequestBuilder
# from .request.calendar_request import CalendarRequest
# from .request.calendar_request_builder import CalendarRequestBuilder
# from .request.outlook_item_request import OutlookItemRequest
# from .request.outlook_item_request_builder import OutlookItemRequestBuilder
# from .request.event_request import EventRequest
# from .request.event_request_builder import EventRequestBuilder
# from .request.conversation_request import ConversationRequest
# from .request.conversation_request_builder import ConversationRequestBuilder
# from .request.profile_photo_request import ProfilePhotoRequest
# from .request.profile_photo_request_builder import ProfilePhotoRequestBuilder
# from .request.drive_request import DriveRequest
# from .request.drive_request_builder import DriveRequestBuilder
# from .request.subscribed_sku_request import SubscribedSkuRequest
# from .request.subscribed_sku_request_builder import SubscribedSkuRequestBuilder
# from .request.organization_request import OrganizationRequest
# from .request.organization_request_builder import OrganizationRequestBuilder
# from .request.user_request import UserRequest
# from .request.user_request_builder import UserRequestBuilder
# from .request.message_request import MessageRequest
# from .request.message_request_builder import MessageRequestBuilder
# from .request.mail_folder_request import MailFolderRequest
# from .request.mail_folder_request_builder import MailFolderRequestBuilder
# from .request.calendar_group_request import CalendarGroupRequest
# from .request.calendar_group_request_builder import CalendarGroupRequestBuilder
# from .request.contact_request import ContactRequest
# from .request.contact_request_builder import ContactRequestBuilder
# from .request.contact_folder_request import ContactFolderRequest
# from .request.contact_folder_request_builder import ContactFolderRequestBuilder
# from .request.attachment_request import AttachmentRequest
# from .request.attachment_request_builder import AttachmentRequestBuilder
# from .request.file_attachment_request import FileAttachmentRequest
# from .request.file_attachment_request_builder import FileAttachmentRequestBuilder
# from .request.item_attachment_request import ItemAttachmentRequest
# from .request.item_attachment_request_builder import ItemAttachmentRequestBuilder
# from .request.event_message_request import EventMessageRequest
# from .request.event_message_request_builder import EventMessageRequestBuilder
# from .request.reference_attachment_request import ReferenceAttachmentRequest
# from .request.reference_attachment_request_builder import ReferenceAttachmentRequestBuilder
# from .request.post_request import PostRequest
# from .request.post_request_builder import PostRequestBuilder
# from .request.drive_item_request import DriveItemRequest
# from .request.drive_item_request_builder import DriveItemRequestBuilder
# from .request.permission_request import PermissionRequest
# from .request.permission_request_builder import PermissionRequestBuilder
# from .request.thumbnail_set_request import ThumbnailSetRequest
# from .request.thumbnail_set_request_builder import ThumbnailSetRequestBuilder
# from .request.subscription_request import SubscriptionRequest
# from .request.subscription_request_builder import SubscriptionRequestBuilder
# from .request.thumbnail_request import ThumbnailRequest
# from .request.thumbnail_request_builder import ThumbnailRequestBuilder
# from .request.threads_collection import ThreadsCollectionRequest, ThreadsCollectionRequestBuilder, ThreadsCollectionPage, ThreadsCollectionResponse
# from .request.calendar_view_collection import CalendarViewCollectionRequest, CalendarViewCollectionRequestBuilder, CalendarViewCollectionPage, CalendarViewCollectionResponse
# from .request.events_collection import EventsCollectionRequest, EventsCollectionRequestBuilder, EventsCollectionPage, EventsCollectionResponse
# from .request.conversations_collection import ConversationsCollectionRequest, ConversationsCollectionRequestBuilder, ConversationsCollectionPage, ConversationsCollectionResponse
# from .request.posts_collection import PostsCollectionRequest, PostsCollectionRequestBuilder, PostsCollectionPage, PostsCollectionResponse
# from .request.events_collection import EventsCollectionRequest, EventsCollectionRequestBuilder, EventsCollectionPage, EventsCollectionResponse
# from .request.calendar_view_collection import CalendarViewCollectionRequest, CalendarViewCollectionRequestBuilder, CalendarViewCollectionPage, CalendarViewCollectionResponse
# from .request.instances_collection import InstancesCollectionRequest, InstancesCollectionRequestBuilder, InstancesCollectionPage, InstancesCollectionResponse
# from .request.attachments_collection import AttachmentsCollectionRequest, AttachmentsCollectionRequestBuilder, AttachmentsCollectionPage, AttachmentsCollectionResponse
# from .request.threads_collection import ThreadsCollectionRequest, ThreadsCollectionRequestBuilder, ThreadsCollectionPage, ThreadsCollectionResponse
# from .request.items_collection import ItemsCollectionRequest, ItemsCollectionRequestBuilder, ItemsCollectionPage, ItemsCollectionResponse
# from .request.special_collection import SpecialCollectionRequest, SpecialCollectionRequestBuilder, SpecialCollectionPage, SpecialCollectionResponse
# from .request.messages_collection import MessagesCollectionRequest, MessagesCollectionRequestBuilder, MessagesCollectionPage, MessagesCollectionResponse
# from .request.mail_folders_collection import MailFoldersCollectionRequest, MailFoldersCollectionRequestBuilder, MailFoldersCollectionPage, MailFoldersCollectionResponse
# from .request.calendars_collection import CalendarsCollectionRequest, CalendarsCollectionRequestBuilder, CalendarsCollectionPage, CalendarsCollectionResponse
# from .request.calendar_groups_collection import CalendarGroupsCollectionRequest, CalendarGroupsCollectionRequestBuilder, CalendarGroupsCollectionPage, CalendarGroupsCollectionResponse
# from .request.calendar_view_collection import CalendarViewCollectionRequest, CalendarViewCollectionRequestBuilder, CalendarViewCollectionPage, CalendarViewCollectionResponse
# from .request.events_collection import EventsCollectionRequest, EventsCollectionRequestBuilder, EventsCollectionPage, EventsCollectionResponse
# from .request.contacts_collection import ContactsCollectionRequest, ContactsCollectionRequestBuilder, ContactsCollectionPage, ContactsCollectionResponse
# from .request.contact_folders_collection import ContactFoldersCollectionRequest, ContactFoldersCollectionRequestBuilder, ContactFoldersCollectionPage, ContactFoldersCollectionResponse
# from .request.attachments_collection import AttachmentsCollectionRequest, AttachmentsCollectionRequestBuilder, AttachmentsCollectionPage, AttachmentsCollectionResponse
# from .request.messages_collection import MessagesCollectionRequest, MessagesCollectionRequestBuilder, MessagesCollectionPage, MessagesCollectionResponse
# from .request.child_folders_collection import ChildFoldersCollectionRequest, ChildFoldersCollectionRequestBuilder, ChildFoldersCollectionPage, ChildFoldersCollectionResponse
# from .request.calendars_collection import CalendarsCollectionRequest, CalendarsCollectionRequestBuilder, CalendarsCollectionPage, CalendarsCollectionResponse
# from .request.contacts_collection import ContactsCollectionRequest, ContactsCollectionRequestBuilder, ContactsCollectionPage, ContactsCollectionResponse
# from .request.child_folders_collection import ChildFoldersCollectionRequest, ChildFoldersCollectionRequestBuilder, ChildFoldersCollectionPage, ChildFoldersCollectionResponse
# from .request.attachments_collection import AttachmentsCollectionRequest, AttachmentsCollectionRequestBuilder, AttachmentsCollectionPage, AttachmentsCollectionResponse
# from .request.permissions_collection import PermissionsCollectionRequest, PermissionsCollectionRequestBuilder, PermissionsCollectionPage, PermissionsCollectionResponse
# from .request.children_collection import ChildrenCollectionRequest, ChildrenCollectionRequestBuilder, ChildrenCollectionPage, ChildrenCollectionResponse
# from .request.thumbnails_collection import ThumbnailsCollectionRequest, ThumbnailsCollectionRequestBuilder, ThumbnailsCollectionPage, ThumbnailsCollectionResponse
# from .request.devices_collection import DevicesCollectionRequest, DevicesCollectionRequestBuilder, DevicesCollectionPage, DevicesCollectionResponse
# from .request.groups_collection import GroupsCollectionRequest, GroupsCollectionRequestBuilder, GroupsCollectionPage, GroupsCollectionResponse
# from .request.directory_roles_collection import DirectoryRolesCollectionRequest, DirectoryRolesCollectionRequestBuilder, DirectoryRolesCollectionPage, DirectoryRolesCollectionResponse
# from .request.directory_role_templates_collection import DirectoryRoleTemplatesCollectionRequest, DirectoryRoleTemplatesCollectionRequestBuilder, DirectoryRoleTemplatesCollectionPage, DirectoryRoleTemplatesCollectionResponse
# from .request.organization_collection import OrganizationCollectionRequest, OrganizationCollectionRequestBuilder, OrganizationCollectionPage, OrganizationCollectionResponse
# from .request.subscribed_skus_collection import SubscribedSkusCollectionRequest, SubscribedSkusCollectionRequestBuilder, SubscribedSkusCollectionPage, SubscribedSkusCollectionResponse
# from .request.users_collection import UsersCollectionRequest, UsersCollectionRequestBuilder, UsersCollectionPage, UsersCollectionResponse
# from .request.drives_collection import DrivesCollectionRequest, DrivesCollectionRequestBuilder, DrivesCollectionPage, DrivesCollectionResponse
# from .request.subscriptions_collection import SubscriptionsCollectionRequest, SubscriptionsCollectionRequestBuilder, SubscriptionsCollectionPage, SubscriptionsCollectionResponse
# from .request.directory_object_check_member_groups import DirectoryObjectCheckMemberGroupsRequest
# from .request.directory_object_get_member_groups import DirectoryObjectGetMemberGroupsRequest
# from .request.directory_object_get_member_objects import DirectoryObjectGetMemberObjectsRequest
# from .request.group_subscribe_by_mail import GroupSubscribeByMailRequest
# from .request.group_unsubscribe_by_mail import GroupUnsubscribeByMailRequest
# from .request.group_add_favorite import GroupAddFavoriteRequest
# from .request.group_remove_favorite import GroupRemoveFavoriteRequest
# from .request.group_reset_unseen_count import GroupResetUnseenCountRequest
# from .request.conversation_thread_reply import ConversationThreadReplyRequest
# from .request.event_accept import EventAcceptRequest
# from .request.event_decline import EventDeclineRequest
# from .request.event_tentatively_accept import EventTentativelyAcceptRequest
# from .request.event_snooze_reminder import EventSnoozeReminderRequest
# from .request.event_dismiss_reminder import EventDismissReminderRequest
# from .request.drive_recent import DriveRecentRequest
# from .request.drive_shared_with_me import DriveSharedWithMeRequest
# from .request.user_assign_license import UserAssignLicenseRequest
# from .request.user_change_password import UserChangePasswordRequest
# from .request.user_send_mail import UserSendMailRequest
# from .request.user_reminder_view import UserReminderViewRequest
# from .request.message_copy import MessageCopyRequest
# from .request.message_move import MessageMoveRequest
# from .request.message_create_reply import MessageCreateReplyRequest
# from .request.message_create_reply_all import MessageCreateReplyAllRequest
# from .request.message_create_forward import MessageCreateForwardRequest
# from .request.message_reply import MessageReplyRequest
# from .request.message_reply_all import MessageReplyAllRequest
# from .request.message_forward import MessageForwardRequest
# from .request.message_send import MessageSendRequest
# from .request.mail_folder_copy import MailFolderCopyRequest
# from .request.mail_folder_move import MailFolderMoveRequest
# from .request.post_forward import PostForwardRequest
# from .request.post_reply import PostReplyRequest
# from .request.drive_item_create_link import DriveItemCreateLinkRequest
# from .request.drive_item_copy import DriveItemCopyRequest
# from .request.drive_item_search import DriveItemSearchRequest
# from .request.drive_item_delta import DriveItemDeltaRequest
# from .request.drive_item_content_request import DriveItemContentRequest, DriveItemContentRequestBuilder
# from .request.thumbnail_content_request import ThumbnailContentRequest, ThumbnailContentRequestBuilder
# from .request.graph_service_client import GraphServiceClient
# from .http_provider import HttpProvider
# from .auth_provider import AuthProvider
# from .session import Session
# from .extensions.graph_client_helper import *
# from .extensions import *
# import sys
