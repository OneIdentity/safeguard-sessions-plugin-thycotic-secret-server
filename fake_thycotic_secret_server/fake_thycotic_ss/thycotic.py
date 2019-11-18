import base64
import datetime
import hashlib
import json
import random
import string
from functools import reduce
from flask import Flask
from flask import abort, request, make_response, session, jsonify

from .database import database

app = Flask(__name__)
app.secret_key = b"This is very secret"


@app.route("/")
def index():
    return make_response(jsonify(message="Hello from fake Thycotic Secret Server"))


@app.route("/oauth2/token", methods=["POST"])
def token_auth():
    user_db = database.get("users", {})
    user_record = user_db.get(request.form.get("username"), {})

    if not user_record:
        abort(make_response(jsonify(error="Login Failed"), 400))

    if user_record.get("password") != request.form.get("password"):
        abort(make_response(jsonify(error="Login failed."), 400))

    if request.form.get("grant_type") != "password":
        abort(make_response(jsonify(error="Invalid grant type"), 400))

    _hash = hashlib.sha256("".join([random.choice(string.ascii_letters) for _ in range(20)]).encode()).hexdigest()
    token = base64.urlsafe_b64encode(bytes(_hash, "utf8")).decode()
    app.open_session(request)
    session["token"] = token

    return make_response(
        jsonify(
            access_token=token,
            token_tpye="bearer",
            refresh_token="this is the refresh token",
            expires_in=1199),
        200)


@app.route("/api/v1/secrets")
def secrets():
    _check_token()

    field_to_search = request.args.get("filter.searchField", "username")

    search_term = request.args.get("filter.searchtext", "")

    paging_of_secret_summary = _create_PagingOfSecretSummary()
    total_count = 0

    include_restricted = json.loads(request.args.get("filter.includeRestricted", False))

    for _, secret in database.get("secrets", {}).items():
        for _, details in secret.items():
            if not include_restricted and details["restricted"]:
                continue
            if search_term in details[field_to_search]:
                total_count += 1
                paging_of_secret_summary["records"].append(_create_SecretSummary(details))

    paging_of_secret_summary["total"] = total_count
    return make_response(jsonify(paging_of_secret_summary))


@app.route("/api/v1/secrets/<secret_id>")
def secret_by_id(secret_id):
    _check_token()

    for _, secret in database.get("secrets", {}).items():
        for _, details in secret.items():
            print(details)
            if str(details["id"]) == secret_id:
                return make_response(jsonify(_create_secret_model(details)))

    abort(make_response(jsonify(error="No secret found with id")), 400)


def _check_token():
    if session.get("token") != _get_token_from_header(request.headers):
        abort(make_response(jsonify(error="Invalid token")))


def _get_token_from_header(headers):
    auth_header = headers.get("Authorization", "")
    if "Bearer " in auth_header:
        return reduce(lambda x, y: x+y, auth_header.split("Bearer "))
    else:
        abort(make_response(jsonify(error="Invalid authorization header")), 400)


def _create_PagingOfSecretSummary():
    # skip: integer (int32)
    # take: integer (int32)
    # total: integer (int32)
    # pageCount: integer (int32)
    # currentPage: integer (int32)
    # batchCount: integer (int32)
    # prevSkip: integer (int32)
    # nextSkip: integer (int32)
    # hasPrev: boolean
    # hasNext: boolean
    # records: object[]
    # sortBy: object[]
    # success: boolean
    # severity: Severity
    return dict(
        skip=0,
        take=1,
        total=0,
        pageCount=1,
        currentPage=1,
        batchCount=1,
        prevSkip=0,
        nextSkip=0,
        hasPrev=False,
        hasNext=False,
        records=[],
        success=True,
        severity=None
    )


def _create_SecretSummary(secret):
    #id: integer (int32)
    # name: string
    # secretTemplateId: integer (int32)
    # secretTemplateName: string
    # folderId: integer (int32)
    # siteId: integer (int32)
    # active: boolean
    # checkedOut: boolean
    # isRestricted: boolean
    # isOutOfSync: boolean
    # outOfSyncReason: string
    # lastHeartBeatStatus: HeartbeatStatus
    # lastPasswordChangeAttempt: string (date-time)
    # responseCodes: string[]
    # lastAccessed: string (date-time)
    # extendedFields: object[]
    # checkOutEnabled: boolean
    # autoChangeEnabled: boolean
    # doubleLockEnabled: boolean
    # requiresApproval: boolean
    # requiresComment: boolean
    # inheritsPermissions: boolean
    # hidePassword: boolean
    # createDate: string (date-time)
    # daysUntilExpiration: integer (int32)
    return dict(
        id=secret["id"],
        name=secret["name"],
        active=secret["active"],
        folderId=1,
        secretTemplateId=1,
        secretTemplateName="Unix(ssh)",
        siteId=1,
        checkedOut=False,
        isRestricted=secret["restricted"],
        lastHeartBeatStatus="Success",
        lassPasswordChangeAttemp="2019-11-10 12:00:00",
        responseCodes=["success", "success"],
        lastAccessed=datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S"),
        extendedFields=[],
        checkOutEnabled=True,
        doubleLockEnabled=False,
        requiresApproval=True,
        requiresComment=False,
        inheritsPermissions=True,
        hidePassword=True,
        createDate="2019-10-29 00:00:01",
        daysUntilExpiration=365,
    )


def _create_secret_model(secret):
    # id: integer (int32)
    # name: string
    # secretTemplateId: integer (int32)
    # folderId: integer (int32)
    # active: boolean
    # items: object[]
    # launcherConnectAsSecretId: integer (int32)
    # checkOutMinutesRemaining: integer (int32)
    # checkedOut: boolean
    # checkOutUserDisplayName: string
    # checkOutUserId: integer (int32)
    # isRestricted: boolean
    # isOutOfSync: boolean
    # outOfSyncReason: string
    # autoChangeEnabled: boolean
    # autoChangeNextPassword: string
    # requiresApprovalForAccess: boolean
    # requiresComment: boolean
    # checkOutEnabled: boolean
    # checkOutIntervalMinutes: integer (int32)
    # checkOutChangePasswordEnabled: boolean
    # accessRequestWorkflowMapId: integer (int32)
    # proxyEnabled: boolean
    # sessionRecordingEnabled: boolean
    # restrictSshCommands: boolean
    # allowOwnersUnrestrictedSshCommands: boolean
    # isDoubleLock: boolean
    # doubleLockId: integer (int32)
    # enableInheritPermissions: boolean
    # passwordTypeWebScriptId: integer (int32)
    # siteId: integer (int32)
    # enableInheritSecretPolicy: boolean
    # secretPolicyId: integer (int32)
    # lastHeartBeatStatus: HeartbeatStatus
    # lastHeartBeatCheck: string (date-time)
    # failedPasswordChangeAttempts: integer (int32)
    # lastPasswordChangeAttempt: string (date-time)
    # secretTemplateName: string
    # responseCodes: string[]
    return dict(
        id=secret["id"],
        name=secret["name"],
        secretTemlateId=1,
        folderId=1,
        active=secret["active"],
        items=[],
        launcherConnectAsSecretId=1,
        checkOutMinutesRemaining=5,
        checkedOut=True,
        checkOutUserDisplayName="user",
        checkOutUserId=11,
        isRestricted=secret["restricted"],
        isOutOfSync=False,
        outOfSyncReason="",
        autoChangeEnabled=False,
        autoChangeNextPassword="",
        requiresApprovalForAccess=True,
        requiresComment=False,
        checkOutEnabled=True,
        checkOutIntervalMinutes=5,
        checkOutChangePasswordEnabled=False,
        accessRequestWorkflowMapId=1,
        proxyEnabled=False,
        sessionRecordingEnabled=False,
        restrictSshCommands=False,
        allowOwnersUnrestrictedSshCommands=True,
        isDoubleLock=False,
        doubleLockId=0,
        enableInheritPermissions=False,
        passwordTypeWebScriptId=1,
        siteId=1,
        enableInheritSecretPolicy=False,
        secretPolicyId=1,
        lastHeartBeatStatus="success",
        lastHeartBeatCheck=datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S"),
        failedPasswordChangeAttempts=0,
        lastPasswordChangeAttempt="2019-10-01 00:00:01",
        secretTemplateName="Unix(ssh)",
        responseCodes=[],
    )
