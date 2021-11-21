import { Category, Event, Invitation, Post, Role, User } from '../datamodel/db-schema';
import { hash, compare } from 'bcrypt';
import { Types } from 'mongoose';
import { IContext } from '..';
import { UserInputError } from 'apollo-server-express';
import { getLoggedIn, mapIds, popId } from './util';
import { usersByUsername } from './Query';

export interface INode {
    _id: string,
}

export interface IUserArg {
    user: string
}

export interface IEventArg {
    event: string,
}

export interface IInvitationArg {
    invitation: string,
}

export interface IPostArg {
    post: string
}

export interface ICategoryArg {
    category: string
}

export interface IEditCategory {
    name: string,
}

export function createCategory(
    parent: undefined,
    { name }: { name: string },
) {
    return Category.create({ name });
}

export function editCategory(
    parent: undefined,
    { category }: { category: IEditCategory & INode },
) {
    const _id = popId(category);
    return Category.findOneAndUpdate({ _id }, { ...category });
}

export function deleteCategory(
    parent: undefined,
    { category }: ICategoryArg,
) {
    return Category.findByIdAndDelete(Types.ObjectId(category));
}

export function assignModerator(
    parent: undefined,
    { category, user }: ICategoryArg & IUserArg,
) {
    return Category.findByIdAndUpdate(
        Types.ObjectId(category),
        { $addToSet: Types.ObjectId(user) },
    );
}

export function removeModerator(
    parent: undefined,
    { category, user }: ICategoryArg & IUserArg,
) {
    return Category.findByIdAndUpdate(
        Types.ObjectId(category),
        { $pull: Types.ObjectId(user) },
    );
}

export interface ICreateUser {
    username: string
    name: string
    surname: string
    password: string
}

const SALT_ROUNDS = 8;

export function createUser(
    parent: undefined,
    { user }: { user: ICreateUser },
) {
    const { username, name, surname, password } = user;
    return hash(password, SALT_ROUNDS).then(
        (hash) => User.create({ username, name, surname, password: hash }));
}

export function login(
    parent: undefined,
    { username, password }: { username: string, password: string },
    ctx: IContext,
) {
    return User.findOne({ username }).then((user) => {
        if (!user) {
            return false;
        }
        return compare(password, user.password).then((checkPassed) => {
            if (checkPassed) {
                const { username, _id, role } = user;
                ctx.session.user = { username, _id: _id.toHexString(), role };
            }
            return checkPassed;
        });
    });
}

export interface IEditUser {
    username?: string,
    name?: string,
    surname?: string,
    password?: string,
}
export function editUser(
    parent: undefined,
    { user }: { user: IEditUser & INode },
) {
    const _id = popId(user);
    if (user.password) {
        return hash(user.password, SALT_ROUNDS).then(
            (password) => User.findOneAndUpdate(
                { _id },
                { ...user, password },
            ),
        );
    } else {
        return User.findOneAndUpdate(
            { _id },
            { ...user },
        );
    }
}

export function setRole(
    parent: undefined,
    { user, role }: IUserArg & { role: Role },
) {
    return User.findByIdAndUpdate(
        Types.ObjectId(user),
        { role },
    );
}

export function deleteUser(parent: undefined, { user }: IUserArg) {
    return User.findByIdAndDelete(Types.ObjectId(user));
}

export function subscribe(
    parent: undefined,
    { categories }: { categories: string[] },
    ctx: IContext,
) {
    return User.findByIdAndUpdate(
        getLoggedIn(ctx),
        { $addToSet: { subscribes: { $each: mapIds(categories) } } },
    );
}

export function unsubscribe(
    parent: undefined,
    { categories }: { categories: string[] },
    ctx: IContext,
) {
    return User.findByIdAndUpdate(
        getLoggedIn(ctx),
        { $pull: { subscribes: { $each: mapIds(categories) } } },
    );
}

export interface ICreateEvent {
    categories?: string[],
    title: string,
    time: Date,
    description?: string,
    location: string,
    private: boolean,
}

export async function createEvent(
    parent: undefined,
    { event }: { event: ICreateEvent },
    ctx: IContext,
) {
    const owner = getLoggedIn(ctx)
    return Event.create({ owner, managers: [owner], attendants: [owner], ...event });
}

export interface IEditEvent {
    title?: string
    time?: Date
    description?: string
    location?: string
    private?: boolean
}

export function editEvent(
    parent: undefined,
    { event }: { event: IEditEvent & INode },
) {
    const _id = popId(event);
    return Event.findOneAndUpdate(
        { _id },
        // Later spreads take higher priority over earlier spread
        { ...event },
    );
}

export function addCategories(
    parent: undefined,
    { categories, event }: { categories: string[] } & IEventArg,
) {
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        {
            $addToSet: {
                categories: { $each: categories.map(Types.ObjectId) },
            }
        },
    )
}

export function removeCategories(
    parent: undefined,
    { categories, event }: { categories: string[] } & IEventArg,
) {
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        {
            $pull: {
                categories: { $in: categories.map(Types.ObjectId) },
            }
        },
    );
}

export function deleteEvent(
    parent: undefined,
    { event }: { event: string },
) {
    return Event.findOneAndDelete({ _id: Types.ObjectId(event) });
}

export interface IUserArg {
    user: string,
}

export function kick(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const uId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        {
            $pull: {
                attendants: uId,
                managers: uId,
            },
        },
    );
}

export function promote(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const userId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        {
            _id: Types.ObjectId(event),
            attendants: userId,
        },
        {
            $addToSet: { managers: userId },
        },
    );
}

export function demote(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const userId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        {
            $pull: { managers: userId },
        },
    );
}

export function invite(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
    ctx: IContext,
) {
    const from = getLoggedIn(ctx);
    const invited = Types.ObjectId(user);
    const to = Types.ObjectId(event);

    return Invitation.create({ from, invited, to });
}

export function acceptInvitation(
    parent: undefined,
    { invitation }: IInvitationArg,
    cxt: IContext,
) {
    return Invitation.findOneAndDelete({ _id: Types.ObjectId(invitation) }).then((invit) => {
        if (invit) {
            return Event.findOneAndUpdate(
                { _id: invit.to },
                { $addToSet: { attendants: invit.invited } },
            );
        }
    })
}

export function declineInvitation(
    parent: undefined,
    { invitation }: IInvitationArg,
    cxt: IContext,
) {
    return Invitation.findOneAndDelete({ _id: Types.ObjectId(invitation) }).then((invit) => {
        if (invit) {
            return Event.findOne({ _id: invit.to });
        }
    })
}

export function request(
    parent: undefined,
    { event }: IEventArg,
    ctx: IContext,
) {
    return Event.findOneAndUpdate(
        { _id: Types.ObjectId(event) },
        { $addToSet: { requests: getLoggedIn(ctx) } },
    );
}

export function acceptRequest(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
    cxt: IContext,
) {
    const userId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        {
            _id: Types.ObjectId(event),
            requests: userId,
        },
        { $pull: { requests: userId }, $addToSet: { attendants: userId } }
    );
}

export function declineRequest(
    parent: undefined,
    { user, event }: IUserArg & IEventArg,
) {
    const userId = Types.ObjectId(user);
    return Event.findOneAndUpdate(
        {
            _id: Types.ObjectId(event),
            requests: userId,
        },
        { $pull: { requests: userId } },
    );
}

export interface ICreatePost {
    postedAt: string
    content: string
}

export function createPost(
    parent: undefined,
    { post }: { post: ICreatePost },
    ctx: IContext,
) {
    const postedAt = Types.ObjectId(post.postedAt);
    return Post.create({ content: post.content, postedAt });
}

export function deletePost(parent: undefined, { post }: IPostArg) {
    return Post.findByIdAndDelete(Types.ObjectId(post));
}

export function flagPost(parent: undefined, { post }: IPostArg) {
    return Post.findByIdAndUpdate(
        Types.ObjectId(post),
        { flagged: true },
    );
}

export function review(
    parent: undefined,
    { post, locked }: IPostArg & { locked: boolean },
    ctx: IContext,
) {
    return Post.findByIdAndUpdate(
        Types.ObjectId(post),
        {
            flagged: false,
            locked
        },
    );
}


export function unlockPost(
    parent: undefined,
    { post }: IPostArg,
    ctx: IContext,
) {
    return Post.findByIdAndUpdate(
        Types.ObjectId(post),
        { locked: false },
    );
}
