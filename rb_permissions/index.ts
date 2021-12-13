import { allow, and, deny, not, or, rule, shield } from 'graphql-shield';
import * as rules from '../permissions/rules';
import { Role } from '../datamodel/db-schema';
import { OR, rbac } from './inheritance';

const { isCaller, Reference } = rules;

const invitedOrManager = or(
    rules.callerIsInvitedToParent,
    rules.callerManagesParent,
);

const publicOrInvitedOrAttending = or(
    not(rules.parentIsPrivate),
    rules.callerIsInvitedToParent,
    rules.callerAttendsParent,
);

const attendantUnlessLocked = and(
    rules.callerAttendsParent,
    or(not(rules.parentIsLocked), rules.callerManagesParent),
);

/**
 * Permissions for not being logged in.
 */
// TODO: Implement!
const DEFAULTS = {
    User: {
        _id: allow,
    },
    Category: {
        _id: allow,
        name: allow,
        events: allow,
    },
    Event: {
        _id: not(rules.parentIsPrivate),
        title: not(rules.parentIsPrivate),
        time: not(rules.parentIsPrivate),
        description: not(rules.parentIsPrivate),
        location: not(rules.parentIsPrivate),
        owner: not(rules.parentIsPrivate),
        private: not(rules.parentIsPrivate),
        attendants: not(rules.parentIsPrivate),
        managers: not(rules.parentIsPrivate),
    },
    Query: {
        events: allow,
    },
    Mutation: {
        createUser: allow,
        login: allow,
    },
};

/**
 * Unique permissions of free users.
 */
// TODO: Implement!
const FREE = {
    User: {
        _id: allow,
        name: allow,
        surname: allow,
        username: allow,
        role: allow,
        moderates: allow,
        attends: isCaller(Reference.PARENT),
        requests: isCaller(Reference.PARENT),
        authored: isCaller(Reference.PARENT),
        subscribes: isCaller(Reference.PARENT),
        invitations: isCaller(Reference.PARENT),
        invites: isCaller(Reference.PARENT),
    },
    Category: {
        _id: allow,
        name: allow,
        events: allow,
        moderators: allow,
    },
    Invitation: {
        _id: invitedOrManager,
        from: invitedOrManager,
        invited: invitedOrManager,
        to: invitedOrManager,
    },
    Event: {
        _id: publicOrInvitedOrAttending,
        title: publicOrInvitedOrAttending,
        time: publicOrInvitedOrAttending,
        description: publicOrInvitedOrAttending,
        location: publicOrInvitedOrAttending,
        owner: publicOrInvitedOrAttending,
        private: publicOrInvitedOrAttending,
        attendants: publicOrInvitedOrAttending,
        managers: publicOrInvitedOrAttending,
        requests: rules.callerManagesParent,
        invited: rules.callerManagesParent,
        messageBoard: rules.callerAttendsParent,
    },
    Post: {
        _id: attendantUnlessLocked,
        content: attendantUnlessLocked,
        author: attendantUnlessLocked,
        postedAt: attendantUnlessLocked,
        flagged: rules.callerManagesParent,
        locked: rules.callerManagesParent,
    },
    Query: {
        users: allow,
        usersByUsername: allow,
        events: allow,
    },
    Mutation: {
        // Users
        createUser: allow,
        login: allow,
        editUser: isCaller(Reference.ARG),
        unsubscribe: allow,

        // Events
        createEvent: not(rules.argIsPrivate),
        editEvent: and(
            rules.callerManagesArg,
            not(rules.argIsPrivate),
        ),
        addCategories: rules.callerManagesArg,
        removeCategories: rules.callerManagesArg,
        // ownsParent? or argument
        deleteEvent: rules.callerOwnsParent,

        // Event management
        kick: and(
            not(and(rules.callerOwnsArg, isCaller(Reference.ARG))),
            or(isCaller(Reference.ARG), rules.callerManagesArg),
        ),
        promote: rules.callerOwnsArg,
        demote: and(rules.callerOwnsArg, not(isCaller(Reference.ARG))),

        // Invitations
        invite: rules.callerManagesArg,
        acceptInvitation: rules.callerIsInvitedToArg,
        declineInvitation: or(
            rules.callerIsInvitedToArg,
            rules.callerManagesArg,
        ),

        // Requests
        request: not(rules.argIsPrivate),
        acceptRequest: rules.callerManagesArg,
        declineRequest: or(rules.callerRequestsArg, rules.callerManagesArg),

        // Posts
        createPost: rules.callerAttendsArg,
        flagPost: rules.callerAttendsArg,
        review: and(rules.argIsFlagged, rules.callerManagesArg),
    },
};

/**
 * Unique permissions of premium users.
 */
// TODO: Implement!
const PREMIUM = {
    Mutation: {
        subscribe: allow,
        createEvent: allow,
        editEvent: allow,
    },
};

/**
 * Unique permissions of moderators.
 */
// TODO: Implement!
const MODERATOR = {
    Category: {
        subscribers: rules.callerModeratesParent,
    },
    Event: {
        messageBoard: rules.callerModeratesParent,
    },
    Post: {
        _id: rules.callerModeratesParent,
        content: rules.callerModeratesParent,
        author: rules.callerModeratesParent,
        postedAt: rules.callerModeratesParent,
        flagged: rules.callerModeratesParent,
        locked: rules.callerModeratesParent,
    },
    Mutation: {
        removeCategories: rules.callerModeratesArg,
        flagPost: rules.callerModeratesArg,
        review: and(rules.argIsFlagged, rules.callerModeratesArg),
    },
};

/**
 * Unique permissions of administrators.
 */
// TODO: Implement!
const ADMINISTRATOR = {
    Category: {
        subscribers: allow,
    },
    Event: {
        messageBoard: allow,
    },
    Post: {
        _id: allow,
        content: allow,
        author: allow,
        postedAt: allow,
        flagged: allow,
        locked: allow,
    },
    Mutation: {
        createCategory: allow,
        editCategory: allow,
        deleteCategory: allow,
        assignModerator: rules.argHasRole(Role.MODERATOR),
        removeModerator: allow,
        setRole: allow,
        deleteUser: allow,
        removeCategories: allow,
        deletePost: rules.argIsLocked,
        flagPost: allow,
        review: rules.argIsFlagged,
        unlockPost: allow,
    },
};

export const permissions = shield(
    rbac({
        [Role.FREE]: FREE,
        [Role.PREMIUM]: OR(FREE, PREMIUM),
        [Role.MODERATOR]: OR(FREE, PREMIUM, MODERATOR),
        [Role.ADMINISTRATOR]: OR(FREE, PREMIUM, MODERATOR, ADMINISTRATOR),
    }, DEFAULTS),
    {
        fallbackRule: deny,
        debug: true,
    },
);
