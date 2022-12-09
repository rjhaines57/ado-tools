#!/usr/bin/python
import json
import os
import sys
import argparse
import re
import linecache

import base64

from datetime import datetime, timedelta
import dateutil
import requests

import pandas as pd
pd.set_option('display.max_rows', 100000)
pd.set_option('display.max_columns', 50)
pd.set_option('display.width', 1000)
pd.set_option('display.max_colwidth', 300)

from types import SimpleNamespace
from azure.devops.credentials import BasicAuthentication
from azure.devops.connection import Connection
from azure.devops.v5_1.work_item_tracking.models import Wiql

def get_coverity_work_items(context):
    wit_client = context.connection.clients.get_work_item_tracking_client()
    project_name = os.getenv('SYSTEM_TEAMPROJECT')
    wiql = Wiql(
        query="""
        select [System.Id],
            [System.WorkItemType],
            [System.Title],
            [System.State],
            [System.AreaPath],
            [System.IterationPath],
            [System.Tags]
        from WorkItems 
        where [System.Title] CONTAINS 'Coverity'
        and [System.TeamProject] == '%s' 
        order by [System.ChangedDate] desc""" % (project_name)
    )
    # We limit number of results to 30 on purpose
    wiql_results = wit_client.query_by_wiql(wiql, top=20).work_items

    work_item_keys = dict()

    if wiql_results != None:
        # WIQL query gives a WorkItemReference with ID only
        # => we get the corresponding WorkItem from id
        work_items = (
            wit_client.get_work_item(int(res.id)) for res in wiql_results
        )
        for work_item in work_items:
          if (debug): print("DEBUG: Matching in title=" + work_item.fields["System.Title"])
          match = re.search('\[(................................)\]', work_item.fields["System.Title"])
          if match:
            finding_key = match.group(1)
            if (debug): print(f"DEBUG: Found key: {finding_key}")
            work_item_keys[finding_key] = work_item

    return work_item_keys

def getAzWorkItems():
  accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
  SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')

  context = SimpleNamespace()
  context.runner_cache = SimpleNamespace()

  # setup the connection
  context.connection = Connection(
    base_url=SYSTEM_COLLECTIONURI,
    creds=BasicAuthentication('PAT', accessToken),
    user_agent='synopsys-azure-tools/1.0')

  work_items_exported = get_coverity_work_items(context)

  return work_items_exported


def getDataFlow(issue,extended_info):
    output_string=""
    event_tree_lines = dict()
    event_tree_events = dict()
    for event in extended_info['events']:
        event_file = event['strippedFilePathname']
        event_line = int(event['lineNumber'])

        if event_file not in event_tree_lines:
            event_tree_lines[event_file] = dict()
            event_tree_events[event_file] = dict()

        event_line_start = event_line - 3
        if (event_line_start < 0): event_line_start = 0
        event_line_end = event_line + 3
        for i in range(event_line_start, event_line_end):
            event_tree_lines[event_file][i] = 1

        if event_line not in event_tree_events[event_file]:
            event_tree_events[event_file][event_line] = []

        event_tree_events[event_file][event_line].append(
            f"{event['eventNumber']}. {event['eventTag']}: {event['eventDescription']}")

    if debug: print(f"DEBUG: event_tree_lines={event_tree_lines}")
    if debug: print(f"DEBUG: event_tree_events={event_tree_events}")

    for filename in event_tree_lines.keys():
        output_string += f"<b>From {filename}:</b>\n"

        output_string += "<pre>\n"
        for i in event_tree_lines[filename].keys():
            if (i in event_tree_events[filename]):
                for event_str in event_tree_events[filename][i]:
                    output_string += f"{event_str}\n"

            code_line = linecache.getline(filename, i)
            output_string += f"%5d {code_line}" % i

        output_string += "</pre>\n"
    return output_string

def generateMarkdown(newIssues,coverity_data):
    with open("summary.md", "w", encoding="utf-8") as f:
        f.write("# Coverity Results\n\n")

        if len(newIssues)==0:
            f.write(f"Coverity Quality/Security check: **Passed** No new issues \n\n")
            return

        url = args.url + f"/query/defects.htm?project={args.project}"

        f.write(f"Coverity Quality/Security check: **Failed** {len(newIssues)} new issues \n\nPlease click [here]("+url+") to view these results in Coverity\n\n")
        formattedIssues=[]
        for issue in newIssues:
            extended_info=coverity_data[issue['mergeKey']]
            formattedIssues.append({ 'CID' : "["+str(issue['cid'])+"]("+ args.url + f"/query/defects.htm?project={args.project}&cid={issue['cid']})", 'Checker' : extended_info['checkerName'] , "Impact" : extended_info['checkerProperties']['impact'],
                                     'File' : extended_info['strippedMainEventFilePathname'] , "Function" :  extended_info['functionDisplayName'] ,
                                     "Line Number" : extended_info['mainEventLineNumber'] } )

        df = pd.DataFrame(formattedIssues)
        df.to_markdown(f,index=False)
        print("Markdown created:")
        print(df)

def modifyAzWorkItem(workitem,azJsonPatches):
    accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
    authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')
    SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')
    SYSTEM_TEAMPROJECT = os.getenv('SYSTEM_TEAMPROJECT')

    id = workitem.id
    url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/wit/workitems/{id}?api-version=6.0"
    headers = {
    'Content-Type': 'application/json-patch+json',
    'Authorization': 'Basic '+ authorization
    }

    if (debug): print("DEBUG: perform API Call to ADO" + url +" : " + json.dumps(azJsonPatches, indent = 4, sort_keys=True) + "\n")
    r = requests.patch(url, json=azJsonPatches, headers=headers)

    if r.status_code == 200:
        print(f"INFO: Success update id {id} to Azure Boards")
        if (debug):
            print(r.text)
        return r.json()
    else:
        print(f"ERROR: Failure updating '{id}' to Azure Boards: Error {r.status_code}")
        print(r.text)


def reopenAzWorkItem(workitem):
    azJsonPatches = []
    azJsonPatch = dict()
    azJsonPatch['op'] = "add"
    azJsonPatch['path'] = "/fields/System.State"
    azJsonPatch['value'] = "Active"
    azJsonPatches.append(azJsonPatch)
    modifyAzWorkItem(workitem,azJsonPatches)


def closeAzWorkItem(workitem):
    azJsonPatches = []
    azJsonPatch = dict()
    azJsonPatch['op'] = "add"
    azJsonPatch['path'] = "/fields/System.State"
    azJsonPatch['value'] = "Closed"
    azJsonPatches.append(azJsonPatch)
    modifyAzWorkItem(workitem,azJsonPatches)



def createAzWorkItem(issue,extended_info):
  accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
  authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')
  SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')
  SYSTEM_TEAMPROJECT = os.getenv('SYSTEM_TEAMPROJECT')


  start_line = extended_info['mainEventLineNumber']
  mergeKey = issue['mergeKey']
  main_file = extended_info['strippedMainEventFilePathname']
  title = "Coverity - " + extended_info['checkerName'] + " in " + main_file + " [" + mergeKey + "]"

  events = extended_info['events']
  remediation = None
  main_desc = None
  for event in events:
      print(f"DEBUG: event={event}")
      if event['remediation'] == True:
          remediation = event['eventDescription']
      if event['main'] == True:
          main_desc = event['eventDescription']

  url = args.url + f"/query/defects.htm?project={args.project}&cid={issue['cid']}"

  checkerProps = extended_info['checkerProperties']
  comment_body = f"<h3>Coverity found issue: {checkerProps['subcategoryShortDescription']} - CWE-{checkerProps['cweCategory']}, {checkerProps['impact']} Severity</h3>\n\n"

  if (main_desc):
      comment_body += f"<b>{extended_info['checkerName']}</b>: {main_desc} {checkerProps['subcategoryLocalEffect']}<p>\n\n"
  else:
      comment_body += f"<b>{extended_info['checkerName']}</b>: {checkerProps['subcategoryLocalEffect']}\n\n"

  if remediation:
      comment_body += f"<b>How to fix:</b> {remediation}<p>\n"

  comment_body += "<h3>Data Flow Path</h3>\n\n"
  comment_body += getDataFlow(issue,extended_info)
  comment_body += f"\n\nIf this is considered to be a false positive or intentional then mark the issue <a href={url}>here</a>\n\n"

  # Tag with merge key
  comment_body += f"<!-- Coverity {issue['mergeKey']} -->"

  azTags = "COVERITY;" + extended_info['checkerName']
  assignedTo = None
  azBugTitle = title
  azArea = ""
  azWorkItemType = "issue"

  azJsonPatches = []

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/fields/System.Title"
  azJsonPatch['value'] = azBugTitle
  azJsonPatches.append(azJsonPatch)

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/fields/System.Description"
  azJsonPatch['value'] = comment_body
  azJsonPatches.append(azJsonPatch)

  #System.AssignedTo
  if (assignedTo != None):
      azJsonPatch = dict()
      azJsonPatch['op'] = "add"
      azJsonPatch['path'] = "/fields/System.AssignedTo"
      azJsonPatch['value'] = assignedTo
      azJsonPatches.append(azJsonPatch)

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/fields/System.Tags"
  azJsonPatch['value'] = azTags
  azJsonPatches.append(azJsonPatch)

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/relations/"
  azHyperlink = dict()
  azHyperlink['rel'] = "Hyperlink"
  azHyperlink['url'] = url

  #azJsonPatch = dict()
  #azJsonPatch['op'] = "add"
  #azJsonPatch['path'] = "/fields/System.AreaPath"
  #azJsonPatch['value'] = ""
  #azJsonPatches.append(azJsonPatch)

  azPost = json.dumps(azJsonPatches)
  if (debug): print("DEBUG: azPost = " + azPost)

  url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/wit/workitems/" \
          f"$" + azWorkItemType + "?api-version=6.0"

  headers = {
    'Content-Type': 'application/json-patch+json',
    'Authorization': 'Basic '+ authorization
  }

  if (debug): print("DEBUG: perform API Call to ADO" + url +" : " + json.dumps(azJsonPatches, indent = 4, sort_keys=True) + "\n")
  r = requests.post(url, json=azJsonPatches, headers=headers)

  if r.status_code == 200:
    print(f"INFO: Success exporting '{title}' to Azure Boards")
    if (debug):
        print(r.text)
    return r.json()
  else:
    print(f"ERROR: Failure exporting '{title}' to Azure Boards: Error {r.status_code}")
    print(r.text)

# -------------------------------------------------------------------------------------
# Pull request stuff
def makeADOCall(endpoint,verb="get",json=None):
    SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')
    SYSTEM_TEAMPROJECT = os.getenv('SYSTEM_TEAMPROJECT')
    url=None
    if not endpoint.startswith("http"):
        url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/{endpoint}"
    else:
        url= endpoint
    if "?" in endpoint:
        url=url+"&api-version=6.0"
    else:
        url = url + "?api-version=6.0"
    accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
    authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')

    headers = {
        'Accept': 'application/json',
        'Authorization': 'Basic ' + authorization,
        'Content-Type' : 'application/json'
    }
    if args.debug: print("DEBUG: perform API Call to ADO" + url + "\n")
    r = requests.request(url=url, headers=headers,method=verb,json=json)
    if r.status_code == 200:
        if args.debug: print("DEBUG: Success")
    else:
            print(f"ERROR: call {url}. Error code: {r.status_code}")
            print(r.text)
            sys.exit(1)
    return r.json()

def cleanupThreadForPatch(thread):
    #Remove contents from pulled threads to allow go back
    del thread['properties']
    del thread['identities']
    del thread['id']
    del thread['pullRequestThreadContext']
    del thread['publishedDate']
    del thread['lastUpdatedDate']
    del thread['threadContext']
    for comment in thread['comments']:
        if globals.debug: print(f"DEBUG: comment={json.dumps(comment, indent=4)}")
        del comment['id']
        del comment['author']
        del comment['publishedDate']
        del comment['lastUpdatedDate']
    return thread

def getLanguage(path):
    filename, filename_extension = os.path.splitext(path)

    if filename_extension == ".js":
        return "javascript", "//", None
    if filename_extension == ".kt":
        return "kotlin", "//", None
    if filename_extension == ".ts" and filename_extension == ".tsx":
        return "typescript", "//", None
    if filename_extension == ".c" :
        return "c", "//", None
    if filename_extension == ".cpp" and filename_extension == ".c++" and filename_extension == ".C" :
        return "c++", "//", None
    if filename_extension == ".java":
        return "java", "//", None
    if filename_extension == ".swift":
        return "swift", "", None
    if filename_extension == ".rb":
        return "ruby", "#", None
    if filename_extension == ".html":
        return "html", "<!--" , "-->"
    if filename_extension == ".xml":
        return "xml", "<!--" , "-->"
    if filename_extension == ".yaml" and filename_extension == ".yml":
        return "yaml" ,"#", None
    if filename_extension == ".json":
        return "json" ,"#", None

    return "java" , "//", None



def getThreads():
    # Get Pull Request Comments
    # Download existing threads so new threads not created over the top.
    SYSTEM_PULLREQUEST_PULLREQUESTID = os.getenv('SYSTEM_PULLREQUEST_PULLREQUESTID')
    BUILD_REPOSITORY_ID = os.getenv('BUILD_REPOSITORY_ID')
    endpoint= f"/git/repositories/{BUILD_REPOSITORY_ID}/pullRequests/{SYSTEM_PULLREQUEST_PULLREQUESTID}/threads"
    threads=makeADOCall(endpoint)['value']

    threads = [x for x in threads if "CoverityUniqueId" in x['properties'] ]
    print(json.dumps(threads,indent=2))
    return threads

def closeThreadAndComment(thread,close_comment):
    url = thread["_links"]['self']['href']
    threadUpdate = dict()
    threadUpdate['status'] = "closed"
    threadUpdate['comments'] = []
    comment = dict()
    comment["commentType"] = 1
    commentContent = close_comment
    comment["content"] = commentContent
    threadUpdate['comments'].append(comment)

    makeADOCall(url, "patch", threadUpdate)

def openThreadAndComment(thread,open_comment):
    url = thread["_links"]['self']['href']
    threadUpdate = dict()
    threadUpdate['status'] = "Active"
    threadUpdate['comments'] = []
    comment = dict()
    comment["commentType"] = 1
    commentContent = open_comment
    comment["content"] = commentContent
    threadUpdate['comments'].append(comment)

    makeADOCall(url, "patch", threadUpdate)

def convertPath(path):
    return path.replace("\\","/")

def annotateAzPullRequests(issue,extended_info):
    az_pr_comments = []

    # Get Pull Request Comments
    # Download existing threads so new threads not created over the top.
    SYSTEM_PULLREQUEST_PULLREQUESTID = os.getenv('SYSTEM_PULLREQUEST_PULLREQUESTID')
    BUILD_REPOSITORY_ID = os.getenv('BUILD_REPOSITORY_ID')
    endpoint= f"/git/repositories/{BUILD_REPOSITORY_ID}/pullRequests/{SYSTEM_PULLREQUEST_PULLREQUESTID}/threads"

    # If we ar here then we need to create a new ticket.
    az_pr_comment = dict()
    properties = dict()
    properties = { "CoverityUniqueId": {
        "$type" : "System.String",
        "$value" : issue['mergeKey']
        }
    }
    comments = []
    comment = dict()
    comment["parentCommentId"] = 0
    comment["commentType"] = 1
    commentContent = ""
    impact=extended_info['checkerProperties']['impact']

    if impact=="High":
        commentContent+=":warning: "
    commentContent+=f"**Coverity  has found an {impact} impact issue with this pull request: {extended_info['checkerName']}** :disappointed:\n\n"
    commentContent+=f"Description: _{extended_info['checkerProperties']['subcategoryLongDescription']}_\n\n"
    if extended_info['checkerProperties']['subcategoryLocalEffect']:
       commentContent+=f"Effect: _{extended_info['checkerProperties']['subcategoryLocalEffect']}_\n\n"

    if "mainEventLineNumber" in extended_info:
        commentContent+=f"Location: _{extended_info['strippedMainEventFilePathname']}_ Line: _{extended_info['mainEventLineNumber']}_"

    commentContent+=getDataFlow(issue,extended_info)

    url = args.url + f"/query/defects.htm?project={args.project}&cid={issue['cid']}"
    commentContent += f"\nView the full issue in Coverity [here]({url})\n\nIf this issue is intentional or a False Positive then please mark it in the Coverity interface and requeue the pull request check\n\n"
    if 'cweCategory' in extended_info['checkerProperties']:
        cwe=extended_info['checkerProperties']['cweCategory']
        commentContent += f"This issue is related to CWE [{cwe}](https://cwe.mitre.org/data/definitions/{cwe}.html)"
    print(commentContent)

    comment["content"] = commentContent
    comments.append(comment)
    az_pr_comment["comments"] = comments

    threadContext = dict()

    rightFileEnd = dict()
    rightFileEnd["line"] = extended_info['mainEventLineNumber']
    rightFileEnd["offset"] = 1

    rightFileStart = dict()
    rightFileStart["line"] = extended_info['mainEventLineNumber']
    rightFileStart["offset"] = 1

    threadContext["filePath"] = "/" + convertPath(extended_info['strippedMainEventFilePathname'])
    threadContext["rightFileEnd"] = rightFileEnd
    threadContext["rightFileStart"] = rightFileStart

    az_pr_comment["threadContext"] = threadContext
    az_pr_comment["properties"] = properties

    az_pr_comment["status"] = "active"

    # Ad commensts to PR
    SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')
    SYSTEM_PULLREQUEST_PULLREQUESTID = os.getenv('SYSTEM_PULLREQUEST_PULLREQUESTID')
    SYSTEM_TEAMPROJECT = os.getenv('SYSTEM_TEAMPROJECT')
    BUILD_REPOSITORY_ID = os.getenv('BUILD_REPOSITORY_ID')
    url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/git/repositories/" \
          f"{BUILD_REPOSITORY_ID}/pullRequests/{SYSTEM_PULLREQUEST_PULLREQUESTID}" \
          "/threads?api-version=6.0"

    accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
    authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')

    headers = {
        'Accept': 'application/json',
        'Authorization': 'Basic ' + authorization
    }

    print("DEBUG: perform API Call to ADO: " + url + " : ")  # + json.dumps(az_pr_comment, indent=4,
#              sort_keys=True) + "\n")
    r = requests.post(url=url, json=az_pr_comment, headers=headers)
    if r.status_code == 200:
        print("DEBUG: Success")
    else:
        print("DEBUG: Failure:" + str(r.status_code))
        print(r.text)


def doPRCleanup():

    # First get a list of all closed PRs
    BUILD_REPOSITORY_ID = os.getenv('BUILD_REPOSITORY_ID')
    endpoint= f"/git/repositories/{BUILD_REPOSITORY_ID}/pullRequests?searchCriteria.status=all"
    prs=makeADOCall(endpoint)['value']
    prs=[x for x in prs if not x['status'] == "active" ]
    for pr in prs:
        close_date=dateutil.parser.isoparse(pr['closedDate'])

        if close_date < datetime.now(close_date.tzinfo)-timedelta(hours=12):
            print(f"PR {pr['pullRequestId']} closed more than 12 hours ago {close_date}")



# -----------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Report on analysis results")
    parser.add_argument('--url', dest='url', help="Connect server URL");
    parser.add_argument('--debug', default=0, help='set debug level [0-9]')

    parser.add_argument('--generateworkitems', action='store_true', dest='generateworkitems' , help='generate work items')
    parser.add_argument('--generatemarkdown', action='store_true', dest='generatemarkdown',
                        help='generate markdown')
    parser.add_argument('--pullrequest', action='store_true', dest='pullrequest' , help='Comment on pull requests')
    parser.add_argument('--prcleanup', action='store_true', dest='prcleanup' , help='Cleanup PR projects')

    group1 = parser.add_argument_group('required arguments')
    group1.add_argument('--project', dest='project', required=True, help="Project name");
    group1.add_argument('--coverity-json', dest='coverity_json', required=True, help="File containing coverity-json-v7 results");
    group1.add_argument('--preview-json', dest='preview_json', required=True,
                        help="File containing coverity preview results");

    max_work_items=10

    args = parser.parse_args()
    debug= args.debug
    cov_user = os.getenv("COV_USER")
    cov_passphrase = os.getenv("COVERITY_PASSPHRASE")

    coverity_json = args.coverity_json
    preview_json = args.preview_json

    coverity_data=dict()
    # Read in coverity results

    if args.prcleanup:
        doPRCleanup()
        sys.exit(1)

    print("INFO: Reading Coverity Raw results from " + coverity_json)
    with open(coverity_json) as f:
         coverity_data_json = json.load(f)
         for issue in coverity_data_json['issues']:
             coverity_data[issue['mergeKey']]=issue;

    print("INFO: Reading Coverity preview results from " + coverity_json)
    with open(preview_json) as f:
         preview_data = json.load(f)

    if (args.debug): print("DEBUG: " + json.dumps(preview_data, indent=4, sort_keys=True) + "\n")
    newIssues=[]
    existingIssues=[]
    allIssues=[]
    for issue in preview_data['issueInfo']:
        allIssues.append(issue)
        print("looking at issue:"+str(issue['cid']))
        if not issue['presentInComparisonSnapshot']:
            print(f"Issue {issue['cid']} with mergeKey {issue['mergeKey']} is new")
            newIssues.append(issue)
        else:
            existingIssues.append(issue)

    print("Total new issues:"+str(len(newIssues)))
    print("Total existing issues:" + str(len(existingIssues)))
    print("Total issues:" + str(len(allIssues)))

    if len(newIssues)>max_work_items and args.generateworkitems:
        print("Cowardly refusing to create more than {max_work_items}")
        sys.exit(1)

    exit_code=0

    if args.generateworkitems:
        print("Getting working items")
        work_items_exported = getAzWorkItems()
        print(f"Got {len(work_items_exported)} existing work items")
        items_to_create = [x for x in newIssues if not x['mergeKey'] in work_items_exported]
        if (len(items_to_create)>0):
            exit_code=1
        print(f"Got {len(items_to_create)} work items to create (after checking which are already created)")
        for issue in items_to_create:
            createAzWorkItem(issue,coverity_data[issue['mergeKey']])
        items_to_close = [x for x in work_items_exported.keys() if (not any(d['mergeKey'] == x for d in allIssues) and work_items_exported[x].fields["System.State"]=="Active") ]
        print(f"Got {len(items_to_close)} work items to close (after checking items are no longer present)")
        for issue in items_to_close:
            closeAzWorkItem(work_items_exported[issue])
        items_to_reopen = [x for x in existingIssues if ( x['mergeKey'] in work_items_exported and work_items_exported[x['mergeKey']].fields["System.State"] == "Closed") and x['triage']['classification'] in ["Bug","Unclassified"] ]
        if (len(items_to_reopen)>0):
            exit_code=1
        print(f"Got {len(items_to_reopen)} work items to reopen (after checking which items still exist but were closed)")
        for issue in items_to_reopen:
            reopenAzWorkItem(work_items_exported[issue['mergeKey']])

    if args.generatemarkdown:
        generateMarkdown(newIssues,coverity_data)

    if args.pullrequest:
        print("Getting existing comment threads")
        existing_threads = getThreads()
        print(f"Got {len(existing_threads)} existing work comment threads")
        items_to_create = [x for x in newIssues if not any(d['properties']["CoverityUniqueId"]['$value'] == x['mergeKey'] for d in existing_threads) ]
        if (len(items_to_create)>0):
            exit_code=1
        print(f"Got {len(items_to_create)} comments to create (after checking which are already created)")
        for issue in items_to_create:
            annotateAzPullRequests(issue,coverity_data[issue['mergeKey']])

        for thread in existing_threads:
            for y in newIssues:
                if thread['status']=='active' and thread['properties']["CoverityUniqueId"]['$value'] == y['mergeKey'] and y['triage']['classification'] in ["Intentional","False Positive"]:
                    closeThreadAndComment(thread,f"Closed by Coverity, marked as {y['triage']['classification']}")
                if thread['status']=='closed' and thread['properties']["CoverityUniqueId"]['$value'] == y['mergeKey'] and y['triage']['classification'] not in ["Intentional","False Positive"]:
                    exit_code = 1
                    openThreadAndComment(thread,f"Reopened by Coverity, please makes sure you mark the issue correctly in the Coverity interface.")

        items_fixed = [x for x in existing_threads if not any(x['properties']["CoverityUniqueId"]['$value'] == d['mergeKey'] for d in newIssues) ]
        print(f"Got {len(items_fixed)} comments for issues that are no longer found in Coverity")
        for thread in items_fixed:
            closeThreadAndComment(thread,f"Coverity has closed this issue as fixed as it can no longer be found")


    # Exit with exit code
    sys.exit(exit_code)

