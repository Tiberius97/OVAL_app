import xml.etree.ElementTree as ET
import json
import optparse

shemas = [
        'http://oval.mitre.org/XMLSchema/oval-common-5',
        'http://oval.mitre.org/XMLSchema/oval-definitions-5',
        'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
        'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
        'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
    ]


class Vulnerability:
    '''Класс описывающией распарсенную уязвимость.'''

    def __init__(self, definition):
        self.vulner_id = definition.attrib['id']
        self.metadata = Metadata(definition)
        self.criteria = criteria_parce(definition.find('.//{*}criteria'), criteria_dict={})

    def to_json(self):
        return json.dumps(self, default=lambda vulner: vulner.__dict__, indent = 4)


class Metadata:
    '''Класс содержащий метаданные уязвимости, такие как её текстовое описаниеб название, инофрмация по CVE,
       и последней дате обновления'''
    
    def CVE_parce(definition):
        CVE_dict = {}
        for elem in definition.findall('.//{*}cve'):
            CVE_dict[elem.text] = elem.attrib
        return CVE_dict

    def __init__(self, definition):
        self.title = definition.find('.//{*}title').text
        self.description = definition.find('.//{*}description').text
        self.CVE = Metadata.CVE_parce(definition) #CVE содержит детальную информацию по уязвимости и ссылки на источники
        self.last_date = definition.find('.//{*}updated').attrib['date']


def criteria_parce(criteria, criteria_dict):
        '''Функция распарсивает критерии в определениях уязвимостей(патчей) из OVAL файла.
        Условное выражение, которое хранилось в  XML формате переформатируется в питоновский словарь. Для
        этого мы реккурсивно обходим условное выражение, и переносим в словарть только нужные критерии, 
        что позволяет упростить его.'''

        exception_list = ['oval:com.redhat.rhba:tst:20191992005', 'oval:com.redhat.rhba:tst:20191992002',
                   'oval:com.redhat.rhba:tst:20191992003', 'oval:com.redhat.rhba:tst:20191992004',
                   'oval:com.redhat.rhba:tst:20192715195', 'oval:com.redhat.rhba:tst:20192715252']

        red_hat_key = 'Red Hat redhatrelease2 key'
        criteria_list = []
        criteria_dict['operator'] = criteria.get('operator')
        criteria_dict['elements'] = criteria_list
        for elem in criteria:
            if elem.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion':
                if elem.get('test_ref') not in exception_list and red_hat_key not in elem.get('comment'):
                    criterion_dict = merge_refers(elem)
                    criteria_list.append(criterion_dict)
            else:
                sub_criteria_dict = criteria_parce(elem, criteria_dict={})# Идём смотреть вложенные критерии
                if sub_criteria_dict is not None:
                    criteria_list.append(sub_criteria_dict)
        if len(criteria_dict['elements']) == 1:
            criteria_dict.pop('operator')
            criteria_dict = criteria_dict['elements'][0]
        elif len(criteria_dict['elements']) == 0:
            criteria_dict = None
        return criteria_dict

def merge_refers(criterion):
    '''Функция соединяет ссылки между определением(патчем)
      и определениями тестов(и связанных с ними состояний и объектов)'''
    test_id = criterion.get('test_ref')
    criterion_dict = criterion.attrib
    test = root.find(f".//*[@id='{test_id}']")
    criterion_dict['check'] = test.get('check')
    object_node = test.find('.//{*}object')
    object_ref = object_node.get('object_ref')
    object_name = root.find(f".//*[@id='{object_ref}']")
    criterion_dict['object'] = parse_object(object_name)
    state_node = test.find('.//{*}state')
    state_ref = state_node.get('state_ref')
    state = root.find(f".//*[@id='{state_ref}']")
    criterion_dict['state'] = parse_state(state)
    return criterion_dict

def parse_object(object_name):
    '''Парсит определения объектов из OVAL файла'''
    object_dict = {}
    for elem in object_name:
        obj = elem.attrib
        obj['object_info'] = elem.text
        key_name = elem.tag
        for shema in shemas: #Удаляем ссылки на схемы
            if shema in key_name:
                key_name = key_name.replace('{' + shema + '}', '')
        object_dict[key_name] = obj
    return object_dict

def parse_state(state):
    '''Парсит определения состояний из OVAL файла'''
    state_dict = {}
    for elem in state:
        condition = elem.attrib
        condition['condition'] = elem.text
        key_name = elem.tag
        for shema in shemas: #Удаляем ссылки на схемы
            if shema in key_name:
                key_name = key_name.replace('{' + shema + '}', '')
        state_dict[key_name] = condition
    return state_dict


def parse_OVAL(path):
    print('Start parsing...')
    definitions = root.findall('.//{*}definition')[:3]
    json_file = {}
    vulnerabilitys = []
    for definition in definitions:
        vulnerability = Vulnerability(definition)
        vulnerability = vulnerability.to_json()
        vulnerability = json.loads(vulnerability)
        vulnerabilitys.append(vulnerability)
    json_file['vulnerabilitys'] = vulnerabilitys
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(json_file, f, indent=4)
    print('File parsed successfully')



parser = optparse.OptionParser()
parser.add_option('-f', '--file', action='store', dest='file', help='Enter file path')
parser.add_option('-o', '--output', action='store', dest='output', help='Enter path for output file')
options, args = parser.parse_args()
if not options.file or not options.output:
    print('Укажите путь до OVAL файла через флаг -f и путь для выходного файла через флаг -o')
    print('Пример: oval_parser.py -f input.xml -o output.json')
    exit()
tree = ET.parse(options.file)
root = tree.getroot()
parse_OVAL(options.output)