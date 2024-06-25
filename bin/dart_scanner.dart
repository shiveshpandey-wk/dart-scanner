import 'dart:io';
import 'dart:convert';
import 'dart:async';

void main(List<String> arguments)async {
  //just for testing purpose we are using sa-tools-data-modeler project. You can replace it with any other project name which do not have gha-dart docker image.
  var projectName = 'sa-tools-data-modeler';
 
  List<String> cvePackageName = [];
  List<Map<String,String>> packageUsedInProject = [];
  
  List<String> projectWithDockerImage = [
    'w_filing',
    'task_portal',
    'forms',
    'permission_editor',
    'highcharts',
    'xbrl-module',
    'cerebral-ui',
    'section16-client',
    'binder-experience',
    'admin_client',
    'home',
    'w_history',
    'workflow_client',
    'w_comments',
    'sa-tools-data-selections',
    'sa-tools-parsing-client',
    'sa-tools-graph-structure',
    'sa-tools-rollforward',
    //'sa-tools-data-modeler',
    'sa-tools-doc-prep-ui',
    'wdesk',
    'wdesk_login',
    'wdesk_sdk'];

  //set your local project path
  var projectPath = Directory('/home/shiveshpandey/Repos/$projectName');
  Directory.current = projectPath;

  await runGrypeCommand(projectWithDockerImage, projectName, cvePackageName);

  if (!projectWithDockerImage.contains(projectName)) {
    print('Resolving dependencies for project:${projectName}');
    var pubGetResult = await Process.start('dart', ['pub', 'get']);

    var seconds = 0;
    var progressTimer = Timer.periodic(Duration(milliseconds: 1000), (timer) {
      seconds++;
      stdout.write('.');
    });

    var exitcode = await pubGetResult.exitCode;
    progressTimer.cancel();
    stdout.write('\n');

    if (exitcode != 0) {
      print('Failed to get dependencies:${pubGetResult.stderr}');
      return;
    }
  }
  
  print('Getting the dependencies tree for project:${projectName}');
  await getDependencytree(packageUsedInProject);

  print('-----------------------------------------------------------------------------------------------------------------');

  print('Fetching root directories for the CVEs');
  checkCVERootDirectories(projectWithDockerImage, projectName, packageUsedInProject, cvePackageName);

}


Future<void> runGrypeCommand(List<String> projectWithDockerImage, String projectName, List<String> cvePackageName) async {
    var grypeGetResult;
    print('Running GRYPE command');
    if (projectWithDockerImage.contains(projectName)) {
      grypeGetResult = await Process.run('grype', ['drydock-prod.workiva.net/workiva/wk:v1', '--scope', 'all-layers', '--only-fixed', '--by-cve', '-o', 'json'], stdoutEncoding: utf8, stderrEncoding: utf8);
    } else {
      grypeGetResult = await Process.run('grype', ['.', '--scope', 'all-layers', '--only-fixed', '--by-cve', '-o', 'json'], stdoutEncoding: utf8, stderrEncoding: utf8);
    }

    var exitCode = await grypeGetResult.exitCode;

    if (exitCode != 0) {
      print('Failed to run GRYPE cmd:${grypeGetResult.stderr}');
      return;
    } else {
      var decodedGrypeJson = jsonDecode(grypeGetResult.stdout);
      print('Decoded GRYPE output:');
      for (var key in decodedGrypeJson.keys) {
        if (key == 'matches') {
          List matches = decodedGrypeJson[key];
          printCveDetails(matches, cvePackageName);
        }
      }
    }
  }


void printCveDetails(List matches,List cvePackageName){
  print('Package'.padRight(12)+' | '+'Version'.padRight(8)+' | '+'Fixed In'.padRight(5)+' | '+'Type'.padRight(3)+' | '+'CVE'.padRight(10)+' | '+'Severity'.padRight(10)+' |');
  if(matches.length > 0){
    for(var match in matches){
      cvePackageName.add(match['artifact']['name']);
      var fixedIn = match['vulnerability']['fix']['versions'][0];
      print('${match['artifact']['name'].padRight(12)} | ${match['artifact']['version'].padRight(8)} | ${fixedIn.padRight(5)} | ${match['artifact']['type'].padRight(3)} | ${match['vulnerability']['id'].padRight(10)} | ${match['vulnerability']['severity'].padRight(10)} |');
    }
  }else{
    print('No CVEs found in the project');
    return;
  }
}

Future<void> getDependencytree(List<Map<String,String>> packageUsedInProject) async {
    var pubDepsResult = await Process.run('dart',['pub','deps','--json']);

    if(pubDepsResult.exitCode != 0){
      print('Failed to get dependencies:${pubDepsResult.stderr}');
      return;   
    }

    try {
      var decodedJson = jsonDecode(pubDepsResult.stdout);
      decodedJson.forEach((key, value) {
        if(key == 'packages'){
          List packages = value;
          for(Map package in packages){
            packageUsedInProject.add({'name':package['name'],'kind':package['kind']});
          }
        }
      });
    } catch (e) {
      print('Failed ro parse dependency tree json:${e}');
    }
  }



void checkCVERootDirectories(List<String> projectWithDockerImage, String projectName, List<Map<String,String>> packageUsedInProject, List<String> cvePackageName) {
    if(!projectWithDockerImage.contains(projectName)){
      var count = 0;
      packageUsedInProject.forEach((package) {
        if(cvePackageName.contains(package['name'])) {
          count++;
          print('Package:${package['name']} is used in project as ${package['kind']}');
        }
      });
      if(count == 0){
        print('No CVE root directories found in the project');
      }
    } else {
      print('${projectName} is using wdesk_sdk_app_server docker image, hence no need to check for root directories');
    }
  }
